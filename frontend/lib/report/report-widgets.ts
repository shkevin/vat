/**
 * Report widget renderers - pure string/HTML generation.
 * No "use client" - safe to import from server (e.g. email API).
 */
import { displaySourceName } from "@/lib/utils";
import type { ReportContext } from "./report-types";
import type { WidgetType } from "./report-types";
import type { SeverityCounts } from "./metrics";
import type { TrendDataPoint } from "./metrics";
import {
  computeTrendData,
  computeTrendDataLastDays,
  computeSlaCompliance,
  computeTrendMetrics,
  getAssetTypeForIssue,
  issueMatchesContainer,
  isOpen,
} from "./metrics";
import type { AgingBucket } from "./metrics";
import type { RepoRiskScore } from "./metrics";
import type { ContainerRiskScore } from "./metrics";
import type { AssetMix } from "./metrics";
import type { ScannerBreakdown } from "./metrics";
import regression from "regression";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sev(s: string): string {
  const l = s.toLowerCase();
  if (l === "critical") return "badge-critical";
  if (l === "high") return "badge-high";
  if (l === "medium") return "badge-medium";
  return "badge-low";
}

function getPrimaryColor(ctx: ReportContext): string {
  return ctx.branding?.primaryColor ?? "#0ea5e9";
}

/** Escape value for HTML data attribute (filtering). */
function filterAttr(v: string | null | undefined): string {
  if (v == null || v === "") return "";
  return String(v)
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;");
}

/** Build space-separated severity list for aggregate widgets (match when any selected). */
function filterAttrSeverities(counts: SeverityCounts): string {
  const order = ["critical", "high", "medium", "low", "info"] as const;
  return order
    .filter((s) => (counts[s] ?? 0) > 0)
    .map((s) => filterAttr(s))
    .join(" ");
}

/** Separator for multi-value repo/branch (avoids splitting names with spaces). */
const REPO_BRANCH_SEP = "|";

/** Build trend-specific filter pills (Issues, Granularity, Date range, Severity, Types) - Aikido-style. */
function buildTrendFilterPills(
  ctx: ReportContext,
  periodDays: number,
  countMode: string,
): string {
  const primary = ctx.branding?.primaryColor ?? "#0ea5e9";
  const pillClass = "trend-filter-pill";
  const daterangeLabel =
    periodDays <= 7
      ? "Last 7 days"
      : periodDays <= 30
        ? "Last 30 days"
        : periodDays <= 90
          ? "Last 90 days"
          : periodDays <= 180
            ? "Last 180 days"
            : "Last 365 days";
  const esc = (s: string) =>
    s.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");
  const issuesPill = `<div class="${pillClass}" data-trend-dim="issues">
    <button type="button" class="trend-filter-pill-trigger" aria-haspopup="listbox">${
      countMode === "instances" ? "Individual Issues" : "Grouped Issues"
    } <span class="trend-filter-arrow">▾</span></button>
    <div class="trend-filter-pill-panel" data-panel="issues">
      <button type="button" class="trend-filter-pill-option" data-value="Individual Issues">Individual Issues</button>
      <button type="button" class="trend-filter-pill-option" data-value="Grouped Issues">Grouped Issues</button>
    </div>
  </div>`;
  const granularityPill = `<div class="${pillClass}" data-trend-dim="granularity">
    <button type="button" class="trend-filter-pill-trigger" aria-haspopup="listbox">Weekly <span class="trend-filter-arrow">▾</span></button>
    <div class="trend-filter-pill-panel" data-panel="granularity">
      <button type="button" class="trend-filter-pill-option" data-value="Daily">Daily</button>
      <button type="button" class="trend-filter-pill-option" data-value="Weekly">Weekly</button>
      <button type="button" class="trend-filter-pill-option" data-value="Monthly">Monthly</button>
    </div>
  </div>`;
  const daterangePill = `<div class="${pillClass}" data-trend-dim="daterange">
    <button type="button" class="trend-filter-pill-trigger" aria-haspopup="listbox">${daterangeLabel} <span class="trend-filter-arrow">▾</span></button>
    <div class="trend-filter-pill-panel" data-panel="daterange">
      <button type="button" class="trend-filter-pill-option" data-value="Last 7 days">Last 7 days</button>
      <button type="button" class="trend-filter-pill-option" data-value="Last 30 days">Last 30 days</button>
      <button type="button" class="trend-filter-pill-option" data-value="Last 90 days">Last 90 days</button>
      <button type="button" class="trend-filter-pill-option" data-value="Last 180 days">Last 180 days</button>
      <button type="button" class="trend-filter-pill-option" data-value="Last 365 days">Last 365 days</button>
    </div>
  </div>`;
  const severityOptions = ["Critical", "High", "Medium", "Low"];
  const severityPill = `<div class="${pillClass}" data-trend-dim="severity">
    <button type="button" class="trend-filter-pill-trigger" aria-haspopup="listbox">All severities <span class="trend-filter-arrow">▾</span></button>
    <div class="trend-filter-pill-panel trend-filter-panel-checkboxes" data-panel="severity">
      <div class="trend-filter-panel-header">Severities</div>
      <button type="button" class="trend-filter-select-all" data-select-all="severity">Select all</button>
      ${severityOptions
        .map(
          (o) =>
            `<label class="trend-filter-checkbox"><input type="checkbox" value="${esc(
              o,
            )}" checked data-trend-severity> ${esc(o)}</label>`,
        )
        .join("")}
    </div>
  </div>`;
  const mix = ctx.assetMix;
  const typeOptions = [
    "Code",
    "Container",
    "VM",
    ...(mix.package && mix.package > 0 ? ["Package"] : []),
    ...(mix.other && mix.other > 0 ? ["Other"] : []),
  ];
  const typesPill = `<div class="${pillClass}" data-trend-dim="types">
    <button type="button" class="trend-filter-pill-trigger" aria-haspopup="listbox">All types <span class="trend-filter-arrow">▾</span></button>
    <div class="trend-filter-pill-panel trend-filter-panel-checkboxes" data-panel="types">
      <div class="trend-filter-panel-header">Show issue type</div>
      <button type="button" class="trend-filter-select-all" data-select-all="types">Select all</button>
      ${typeOptions
        .map(
          (o) =>
            `<label class="trend-filter-checkbox"><input type="checkbox" value="${esc(
              o,
            )}" checked data-trend-type> ${esc(o)}</label>`,
        )
        .join("")}
    </div>
  </div>`;
  return `<div class="trend-filter-bar" style="--trend-primary:${primary}">${issuesPill}${granularityPill}${daterangePill}${severityPill}${typesPill}</div>`;
}

/** Find container name that matches the given repo, or null. */
function findMatchingContainer(
  repo: string | undefined,
  containerRisk: { repo: string }[],
): string | null {
  if (!repo?.trim()) return null;
  const match = containerRisk.find((c) => issueMatchesContainer(repo, c.repo));
  return match ? match.repo : null;
}

/** Build filter wrapper attrs for aggregate widgets. Only adds attrs when non-empty. */
function sectionFilterAttrs(ctx: ReportContext): string {
  const sev = filterAttrSeverities(ctx.counts);
  const repos = [...new Set(ctx.repoRisk.map((r) => r.repo).filter(Boolean))];
  const branches = [
    ...new Set(ctx.filteredIssues.map((i) => i.branch).filter(Boolean)),
  ];
  const containers = [
    ...new Set(ctx.containerRisk.map((c) => c.repo).filter(Boolean)),
  ];
  const scanners = [
    ...new Set(
      ctx.filteredIssues
        .map(
          (i) =>
            displaySourceName(i.scanner_type) || i.scanner_type || "Unknown",
        )
        .filter(Boolean),
    ),
  ];
  const parts: string[] = [];
  if (sev) parts.push(`data-filter-severity="${sev}"`);
  if (repos.length > 0)
    parts.push(
      `data-filter-repo="${repos
        .map((r) => filterAttr(r))
        .join(REPO_BRANCH_SEP)}"`,
    );
  if (branches.length > 0)
    parts.push(
      `data-filter-branch="${branches
        .map((b) => filterAttr(b))
        .join(REPO_BRANCH_SEP)}"`,
    );
  if (containers.length > 0)
    parts.push(
      `data-filter-container="${containers
        .map((c) => filterAttr(c))
        .join(REPO_BRANCH_SEP)}"`,
    );
  if (scanners.length > 0)
    parts.push(
      `data-filter-scanner="${scanners
        .map((s) => filterAttr(s))
        .join(REPO_BRANCH_SEP)}"`,
    );
  return parts.length > 0 ? " " + parts.join(" ") : "";
}

function sevColor(s: string, primaryColor = "#0ea5e9"): string {
  const t = s.toLowerCase();
  if (t === "critical") return "#ef4444";
  if (t === "high") return "#f97316";
  if (t === "medium") return "#eab308";
  return primaryColor;
}

// ---------------------------------------------------------------------------
// SVG helpers (print-safe)
// ---------------------------------------------------------------------------

function svgSeverityDonut(
  counts: SeverityCounts,
  total: number,
  size = 100,
  primaryColor = "#0ea5e9",
): string {
  const cx = size / 2;
  const r = size / 2 - 4;
  if (total === 0)
    return `<svg viewBox="0 0 ${size} ${size}" class="viz-donut" width="${size}" height="${size}"><circle cx="${cx}" cy="${cx}" r="${r}" fill="#f1f5f9"/><text x="${cx}" y="${
      cx + 4
    }" text-anchor="middle" font-size="12" fill="#64748b">0</text></svg>`;
  const colors = ["#ef4444", "#f97316", "#eab308", primaryColor];
  const keys: (keyof SeverityCounts)[] = ["critical", "high", "medium", "low"];
  let offset = 0;
  const segments = keys
    .map((k, i) => {
      const cnt = counts[k];
      if (cnt <= 0) return "";
      const pct = cnt / total;
      const dash = pct * 100;
      const seg = `<circle cx="${cx}" cy="${cx}" r="${r}" fill="none" stroke="${
        colors[i]
      }" stroke-width="8" pathLength="100" stroke-dasharray="${dash} ${
        100 - dash
      }" stroke-dashoffset="${-offset}" transform="rotate(-90 ${cx} ${cx})"/>`;
      offset += dash;
      return seg;
    })
    .join("");
  return `<svg viewBox="0 0 ${size} ${size}" class="viz-donut" width="${size}" height="${size}"><circle cx="${cx}" cy="${cx}" r="${r}" fill="none" stroke="#e2e8f0" stroke-width="8" pathLength="100"/>${segments}<text x="${cx}" y="${
    cx + 5
  }" text-anchor="middle" font-size="14" font-weight="700" fill="#0f172a">${total}</text></svg>`;
}

function svgRiskGauge(score: number, size = 120): string {
  const cx = size / 2;
  const cy = size / 2;
  const r = size / 2 - 6;
  const fillColor =
    score >= 75
      ? "#ef4444"
      : score >= 50
        ? "#f97316"
        : score >= 25
          ? "#eab308"
          : "#22c55e";
  const pct = Math.min(100, Math.max(0, score)) / 100;
  return `<svg viewBox="0 0 ${size} ${size}" class="viz-gauge" width="${size}" height="${size}"><path d="M 6 ${cy} A ${r} ${r} 0 0 1 ${
    size - 6
  } ${cy}" fill="none" stroke="#e2e8f0" stroke-width="8" pathLength="100"/><path d="M 6 ${cy} A ${r} ${r} 0 0 1 ${
    size - 6
  } ${cy}" fill="none" stroke="${fillColor}" stroke-width="8" pathLength="100" stroke-dasharray="${
    pct * 100
  } 100" stroke-linecap="round"/><text x="${cx}" y="${
    cy + 4
  }" text-anchor="middle" font-size="18" font-weight="700" fill="${fillColor}">${score}</text></svg>`;
}

function svgTrendSparkline(
  trends: TrendDataPoint[],
  w = 280,
  h = 56,
  primaryColor = "#0ea5e9",
): string {
  if (trends.length === 0) return "";
  const max = Math.max(1, ...trends.map((t) => t.total));
  const pad = 4;
  const x0 = pad;
  const y0 = pad;
  const gw = w - pad * 2;
  const gh = h - pad * 2;
  const points = trends
    .map((t, i) => {
      const x = x0 + (i / Math.max(1, trends.length - 1)) * gw;
      const y = y0 + gh - (t.total / max) * gh;
      return `${x},${y}`;
    })
    .join(" ");
  return `<svg viewBox="0 0 ${w} ${h}" class="viz-sparkline" width="100%" height="${h}"><polyline fill="none" stroke="${primaryColor}" stroke-width="2" points="${points}"/></svg>`;
}

function svgAgingBars(
  aging: AgingBucket[],
  maxW = 200,
  primaryColor = "#0ea5e9",
): string {
  const totalMax = Math.max(
    1,
    ...aging.map((b) => b.critical + b.high + b.medium + b.low),
  );
  return aging
    .map((b) => {
      const total = b.critical + b.high + b.medium + b.low;
      if (total === 0) return "";
      const w = Math.max(2, (total / totalMax) * maxW);
      const sevs: string[] = [];
      if (b.critical > 0) sevs.push("critical");
      if (b.high > 0) sevs.push("high");
      if (b.medium > 0) sevs.push("medium");
      if (b.low > 0) sevs.push("low");
      const sevAttr =
        sevs.length > 0
          ? ` data-filter-severity="${filterAttr(sevs.join(" "))}"`
          : "";
      return `<div class="aging-bar-row"${sevAttr}><span class="aging-bar-label">${
        b.range
      }</span><div class="aging-bar-track"><div class="aging-bar-fill" style="width:${w}px;background:linear-gradient(90deg,#ef4444 ${
        (b.critical / total) * 100
      }%,#f97316 ${(b.critical / total) * 100}% ${
        ((b.critical + b.high) / total) * 100
      }%,#eab308 ${((b.critical + b.high) / total) * 100}% ${
        ((b.critical + b.high + b.medium) / total) * 100
      }%,${primaryColor} ${
        ((b.critical + b.high + b.medium) / total) * 100
      }%)"></div></div><span class="aging-bar-num">${total}</span></div>`;
    })
    .join("");
}

function svgRepoRiskBars(
  repos: RepoRiskScore[],
  maxScore = 100,
  maxRepos = 8,
): string {
  const top = repos.slice(0, maxRepos);
  return top
    .map((repo) => {
      const w = Math.max(0, (repo.score / maxScore) * 120);
      const sevs: string[] = [];
      if (repo.critical > 0) sevs.push("critical");
      if (repo.high > 0) sevs.push("high");
      if (repo.medium > 0) sevs.push("medium");
      if (repo.low > 0) sevs.push("low");
      const sevAttr =
        sevs.length > 0
          ? ` data-filter-severity="${filterAttr(sevs.join(" "))}"`
          : "";
      return `<div class="repo-bar-row report-filterable" data-filter-repo="${filterAttr(
        repo.repo,
      )}" data-filter-asset-type="${filterAttr(
        "Code",
      )}"${sevAttr}><span class="repo-bar-label mono" title="${repo.repo}">${
        repo.repo.length > 24 ? repo.repo.slice(0, 21) + "…" : repo.repo
      }</span><div class="repo-bar-track"><div class="repo-bar-fill ${
        repo.critical > 0
          ? "repo-bar-critical"
          : repo.high > 0
            ? "repo-bar-high"
            : ""
      }" style="width:${w}px"></div></div><span class="repo-bar-num">${
        repo.score
      }</span></div>`;
    })
    .join("");
}

function svgContainerRiskBars(
  containers: ContainerRiskScore[],
  maxScore = 100,
  maxContainers = 8,
): string {
  const top = containers.slice(0, maxContainers);
  return top
    .map((c) => {
      const w = Math.max(0, (c.score / maxScore) * 120);
      const sevs: string[] = [];
      if (c.critical > 0) sevs.push("critical");
      if (c.high > 0) sevs.push("high");
      if (c.medium > 0) sevs.push("medium");
      if (c.low > 0) sevs.push("low");
      const sevAttr =
        sevs.length > 0
          ? ` data-filter-severity="${filterAttr(sevs.join(" "))}"`
          : "";
      const containerAttr = ` data-filter-container="${filterAttr(c.repo)}"`;
      return `<div class="repo-bar-row report-filterable" data-filter-repo="${filterAttr(
        c.repo,
      )}" data-filter-asset-type="${filterAttr(
        "Container",
      )}"${containerAttr}${sevAttr}><span class="repo-bar-label mono" title="${
        c.repo
      }">${
        c.repo.length > 24 ? c.repo.slice(0, 21) + "…" : c.repo
      }</span><div class="repo-bar-track"><div class="repo-bar-fill ${
        c.critical > 0 ? "repo-bar-critical" : c.high > 0 ? "repo-bar-high" : ""
      }" style="width:${w}px"></div></div><span class="repo-bar-num">${
        c.score
      }</span></div>`;
    })
    .join("");
}

function svgAssetMixDonut(
  mix: AssetMix,
  total: number,
  size = 100,
  primaryColor = "#0ea5e9",
): string {
  const cx = size / 2;
  const r = size / 2 - 4;
  if (total === 0)
    return `<svg viewBox="0 0 ${size} ${size}" class="viz-donut" width="${size}" height="${size}"><circle cx="${cx}" cy="${cx}" r="${r}" fill="#f1f5f9"/><text x="${cx}" y="${
      cx + 4
    }" text-anchor="middle" font-size="12" fill="#64748b">0</text></svg>`;
  const segments = [
    { count: mix.code, color: primaryColor },
    { count: mix.container, color: "#8b5cf6" },
    { count: mix.vm, color: "#ec4899" },
    { count: mix.package ?? 0, color: "#22c55e" },
    { count: mix.other, color: "#94a3b8" },
  ].filter((s) => s.count > 0);
  let offset = 0;
  const circles = segments
    .map((s) => {
      const dash = (s.count / total) * 100;
      const seg = `<circle cx="${cx}" cy="${cx}" r="${r}" fill="none" stroke="${
        s.color
      }" stroke-width="8" pathLength="100" stroke-dasharray="${dash} ${
        100 - dash
      }" stroke-dashoffset="${-offset}" transform="rotate(-90 ${cx} ${cx})"/>`;
      offset += dash;
      return seg;
    })
    .join("");
  return `<svg viewBox="0 0 ${size} ${size}" class="viz-donut" width="${size}" height="${size}"><circle cx="${cx}" cy="${cx}" r="${r}" fill="none" stroke="#e2e8f0" stroke-width="8" pathLength="100"/>${circles}<text x="${cx}" y="${
    cx + 5
  }" text-anchor="middle" font-size="14" font-weight="700" fill="#0f172a">${total}</text></svg>`;
}

const SCANNER_DONUT_COLORS = [
  "#0ea5e9",
  "#8b5cf6",
  "#ec4899",
  "#f97316",
  "#22c55e",
  "#64748b",
  "#eab308",
  "#94a3b8",
];

function svgScannerDonut(
  scanners: ScannerBreakdown[],
  total: number,
  size = 100,
): string {
  const cx = size / 2;
  const r = size / 2 - 4;
  if (total === 0 || scanners.length === 0)
    return `<svg viewBox="0 0 ${size} ${size}" class="viz-donut" width="${size}" height="${size}"><circle cx="${cx}" cy="${cx}" r="${r}" fill="#f1f5f9"/><text x="${cx}" y="${
      cx + 4
    }" text-anchor="middle" font-size="12" fill="#64748b">0</text></svg>`;
  let offset = 0;
  const segments = scanners
    .map((s, i) => {
      const pct = s.count / total;
      const dash = pct * 100;
      const color = SCANNER_DONUT_COLORS[i % SCANNER_DONUT_COLORS.length];
      const seg = `<circle cx="${cx}" cy="${cx}" r="${r}" fill="none" stroke="${color}" stroke-width="8" pathLength="100" stroke-dasharray="${dash} ${
        100 - dash
      }" stroke-dashoffset="${-offset}" transform="rotate(-90 ${cx} ${cx})"/>`;
      offset += dash;
      return seg;
    })
    .join("");
  return `<svg viewBox="0 0 ${size} ${size}" class="viz-donut" width="${size}" height="${size}"><circle cx="${cx}" cy="${cx}" r="${r}" fill="none" stroke="#e2e8f0" stroke-width="8" pathLength="100"/>${segments}<text x="${cx}" y="${
    cx + 5
  }" text-anchor="middle" font-size="14" font-weight="700" fill="#0f172a">${total}</text></svg>`;
}

// Stack order bottom→top: critical, high, medium, low (reference style). Colors: red, orange, blue, teal.
const TREND_STACKED_COLORS = [
  "#ef4444",
  "#f97316",
  "#3b82f6",
  "#14b8a6",
] as const;
const TREND_STACKED_KEYS: (keyof Omit<TrendDataPoint, "date" | "total">)[] = [
  "critical",
  "high",
  "medium",
  "low",
];
const TREND_STACKED_LABELS = ["critical", "high", "medium", "low"] as const;

function niceMax(value: number): number {
  if (value <= 0) return 100;
  const step =
    value <= 10
      ? 1
      : value <= 50
        ? 10
        : value <= 200
          ? 50
          : value <= 500
            ? 100
            : 200;
  return Math.ceil(value / step) * step;
}

const TREND_LEGEND_LEFT = 76;

const TREND_LINE_COLOR = "#fbbf24";

/** Linear regression on totals using regression-js. Caller must pass only buckets with data (total > 0). */
function linearRegressionLine(
  trends: TrendDataPoint[],
  yMax: number,
  pad: { left: number; top: number },
  chartW: number,
  chartH: number,
  barW: number,
  gap: number,
): string {
  const n = trends.length;
  if (n < 2) return "";
  const data = trends.map((t, i) => [i, t.total] as [number, number]);
  const result = regression.linear(data);
  const points: string[] = [];
  const steps = Math.max(n * 4, 16);
  for (let k = 0; k <= steps; k++) {
    const i = (k / steps) * (n - 1);
    const [, val] = result.predict(i);
    const clamped = Math.max(0, val);
    const x = pad.left + i * (barW + gap) + barW / 2;
    const y = pad.top + chartH - (clamped / yMax) * chartH;
    points.push(`${x},${y}`);
  }
  const d = `M ${points.join(" L ")}`;
  return `<path d="${d}" fill="none" stroke="${TREND_LINE_COLOR}" stroke-width="2" stroke-dasharray="4 2" stroke-linecap="round" stroke-linejoin="round"/>`;
}

function svgTrendStacked(trends: TrendDataPoint[], w = 560, h = 160): string {
  if (trends.length === 0) return "";
  const maxTotal = Math.max(1, ...trends.map((t) => t.total));
  const yMax = niceMax(maxTotal);
  const pad = { left: TREND_LEGEND_LEFT, right: 40, top: 24, bottom: 28 };
  const chartW = w - pad.left - pad.right;
  const chartH = h - pad.top - pad.bottom;
  const n = trends.length;
  const gap = 2;
  const barW = Math.max(4, (chartW - (n - 1) * gap) / n);
  const barRects: string[] = [];
  const tooltips: string[] = [];
  const segIds: string[] = [];
  for (let i = 0; i < n; i++) {
    const t = trends[i];
    const x = pad.left + i * (barW + gap);
    let y = pad.top + chartH;
    TREND_STACKED_KEYS.forEach((k, ki) => {
      const cnt = t[k];
      if (cnt <= 0) return;
      const segH = (cnt / yMax) * chartH;
      y -= segH;
      const label = TREND_STACKED_LABELS[ki];
      const tooltipText = `${t.date}: ${label} ${cnt}`
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
      const segHeight = Math.max(1, segH);
      const cx = x + barW / 2;
      const ty = Math.max(pad.top - 8, y - 6);
      const segId = `t${i}-${ki}`;
      segIds.push(segId);
      barRects.push(
        `<g class="trend-segment"><rect data-segment="${segId}" x="${x}" y="${y}" width="${barW}" height="${segHeight}" fill="${TREND_STACKED_COLORS[ki]}" rx="0"/></g>`,
      );
      const approxCharWidth = 5.5;
      const padding = 10;
      const tooltipW = Math.max(
        64,
        Math.ceil(tooltipText.length * approxCharWidth) + padding * 2,
      );
      const halfW = tooltipW / 2;
      tooltips.push(
        `<g class="trend-segment-tooltip" data-for="${segId}" transform="translate(${cx},${ty})" text-anchor="middle"><rect x="${-halfW}" y="-10" width="${tooltipW}" height="16" fill="rgba(15,23,42,0.94)" rx="4" stroke="#64748b" stroke-width="0.5"/><text x="0" y="2" font-size="9" fill="#fff">${tooltipText}</text></g>`,
      );
    });
  }
  const xAxisY = pad.top + chartH;
  const axisLine = `<line x1="${pad.left}" y1="${xAxisY}" x2="${
    pad.left + chartW
  }" y2="${xAxisY}" stroke="#e2e8f0" stroke-width="1"/>`;
  const yAxisLine = `<line x1="${pad.left + chartW}" y1="${pad.top}" x2="${
    pad.left + chartW
  }" y2="${xAxisY}" stroke="#e2e8f0" stroke-width="1"/>`;
  const yTicks = [
    0,
    Math.ceil(yMax / 4),
    Math.ceil(yMax / 2),
    Math.ceil((3 * yMax) / 4),
    yMax,
  ].filter((v, i, a) => a.indexOf(v) === i);
  const yLabels = yTicks
    .map((v) => {
      const y = pad.top + chartH - (v / yMax) * chartH;
      return `<text x="${pad.left + chartW + 6}" y="${
        y + 4
      }" text-anchor="start" font-size="10" fill="#64748b">${v}</text>`;
    })
    .join("");
  const maxXLabels = 14;
  const xLabelIndices =
    n <= maxXLabels
      ? Array.from({ length: n }, (_, i) => i)
      : Array.from({ length: maxXLabels }, (_, k) =>
          Math.round((k * (n - 1)) / (maxXLabels - 1)),
        );
  const xLabels = xLabelIndices
    .map((i) => {
      const t = trends[i];
      const x = pad.left + i * (barW + gap) + barW / 2;
      return `<text x="${x}" y="${
        h - 6
      }" text-anchor="middle" font-size="9" fill="#64748b">${t.date}</text>`;
    })
    .join("");
  const legendX = 10;
  const legend = TREND_STACKED_LABELS.map((label, i) => {
    const ly = pad.top - 2 + i * 14;
    return `<circle cx="${legendX}" cy="${ly}" r="4" fill="${
      TREND_STACKED_COLORS[i]
    }"/><text x="${legendX + 10}" y="${
      ly + 4
    }" text-anchor="start" font-size="10" fill="#475569">${label}</text>`;
  }).join("");
  const trendLegendLy = pad.top - 2 + 4 * 14;
  const trendLegend =
    n >= 2
      ? `<line x1="${legendX}" y1="${trendLegendLy}" x2="${
          legendX + 12
        }" y2="${trendLegendLy}" stroke="${TREND_LINE_COLOR}" stroke-width="2" stroke-dasharray="4 2"/><text x="${
          legendX + 16
        }" y="${
          trendLegendLy + 4
        }" text-anchor="start" font-size="10" fill="#475569">Trend</text>`
      : "";
  const hoverCss = segIds
    .map(
      (id) =>
        `.viz-trend-stacked-container:has(.viz-trend-stacked [data-segment="${id}"]:hover) .viz-trend-stacked-overlay [data-for="${id}"]{opacity:1}`,
    )
    .join("");
  const tooltipLayer = `<g class="trend-tooltip-layer">${tooltips.join(
    "",
  )}</g>`;
  const regressionLine = linearRegressionLine(
    trends,
    yMax,
    pad,
    chartW,
    chartH,
    barW,
    gap,
  );
  return `<div class="viz-trend-stacked-container" style="position:relative;width:100%;height:100%;min-height:140px"><svg viewBox="0 0 ${w} ${h}" class="viz-trend-stacked" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">${legend}${trendLegend}${axisLine}${yAxisLine}${barRects.join(
    "",
  )}${regressionLine}${yLabels}${xLabels}</svg><svg viewBox="0 0 ${w} ${h}" class="viz-trend-stacked-overlay" width="100%" height="100%" preserveAspectRatio="xMidYMid meet" style="position:absolute;top:0;left:0;pointer-events:none"><defs><style>.trend-segment-tooltip{opacity:0;transition:opacity .03s ease-out}${hoverCss}</style></defs>${tooltipLayer}</svg></div>`;
}

// ---------------------------------------------------------------------------
// Widget renderers: (context, config) => HTML string
// ---------------------------------------------------------------------------

/** Trend badge: up/down arrow + percentage. Block (below value) or inline.
 * improvementIsUp: when true, up = good = green; else down = good = green. */
function trendBadgeHtml(
  change: { pctChange: number; direction: "up" | "down" | "flat" } | undefined,
  inline = false,
  improvementIsUp = false,
): string {
  if (!change || change.direction === "flat" || change.pctChange === 0)
    return "";
  const arrow = change.direction === "up" ? "↑" : "↓";
  const pct = Math.abs(change.pctChange);
  const isGood = improvementIsUp
    ? change.direction === "up"
    : change.direction === "down";
  const color = isGood ? "#16a34a" : "#dc2626";
  const style = `color:${color}`;
  return inline
    ? `<span class="kpi-trend kpi-trend-inline" style="${style}">${arrow} ${pct}%</span>`
    : `<span style="${style}">${arrow} ${pct}%</span>`;
}

/** Uniform KPI card: label, value, optional trend, detail. Always renders kpi-trend div for client-side updates. */
function kpiCard(
  ctx: ReportContext,
  label: string,
  valueHtml: string,
  trend: string,
  detail: string,
): string {
  return `<div class="kpi-card"><div class="kpi-label">${label}</div><div class="kpi-value">${valueHtml}</div><div class="kpi-trend">${trend}</div><div class="kpi-detail">${detail}</div></div>`;
}

function renderSummary(
  ctx: ReportContext,
  config: Record<string, unknown>,
): string {
  const variant = (config.variant as string) || "default";
  const criticalHigh = ctx.counts.critical + ctx.counts.high;
  const pc = ctx.periodChange;
  const filterParts: string[] = [];
  if (ctx.repoFilter.length > 0) {
    filterParts.push(
      ctx.repoFilter.length === 1
        ? `repo: ${ctx.repoFilter[0]}`
        : `repos: ${ctx.repoFilter.join(", ")}`,
    );
  }
  if (ctx.branchFilter) filterParts.push(`branch: ${ctx.branchFilter}`);
  const filterNote =
    filterParts.length > 0
      ? `<p class="filter-note">Filtered to: <strong>${filterParts.join(
          ", ",
        )}</strong></p>`
      : "";
  const notes = ctx.notes
    ? `<div class="notes"><strong>Notes:</strong> ${ctx.notes}</div>`
    : "";

  const riskColor = sevColor(ctx.riskLevel, getPrimaryColor(ctx));
  const cards = [
    kpiCard(
      ctx,
      "Risk Score",
      `<span style="color:${riskColor}">${ctx.riskScore}</span><span class="kpi-suffix">/100</span>`,
      trendBadgeHtml(pc?.riskScore ?? undefined),
      ctx.riskLevel,
    ),
    kpiCard(
      ctx,
      "Open",
      String(ctx.openIssues),
      trendBadgeHtml(pc?.openIssues),
      `${ctx.counts.critical} critical`,
    ),
    kpiCard(
      ctx,
      "Critical + High",
      `<span style="color:#f97316">${criticalHigh}</span>`,
      trendBadgeHtml(pc?.criticalHigh),
      "In scope",
    ),
    kpiCard(
      ctx,
      "Avg MTTR",
      ctx.avgMttr !== undefined && Number.isFinite(ctx.avgMttr)
        ? String(ctx.avgMttr)
        : "—",
      trendBadgeHtml(pc?.mttr ?? undefined),
      ctx.avgMttr !== undefined ? "days" : "No data",
    ),
  ];

  const grid = `<div class="kpi-grid">${cards.join("")}</div>`;
  /* Summary is an aggregate widget: always visible, content updated by client-side filter script */
  const summaryFilter = "";

  if (variant === "board") {
    const narrative =
      ctx.openIssues === 0
        ? "No open vulnerabilities. Risk posture is healthy."
        : criticalHigh > 0
          ? `There are ${ctx.openIssues} open findings; ${criticalHigh} are critical or high and require prioritization.`
          : `${ctx.openIssues} open findings, predominantly medium and low severity.`;
    const tooltipAttr = ` data-tooltip="${ORA_INFO_TITLE.replace(
      /"/g,
      "&quot;",
    )}"`;
    return `<div class="section section-board-summary" data-report-aggregate="summary"><div${summaryFilter}><h2${tooltipAttr}>Risk at a glance</h2>${filterNote}<div class="board-hero"><div class="board-hero-viz">${svgRiskGauge(
      ctx.riskScore,
    )}</div><div class="board-hero-text"><div class="board-risk-score" style="color:${riskColor}">${
      ctx.riskScore
    }<span class="board-risk-max">/100</span>${trendBadgeHtml(
      pc?.riskScore ?? undefined,
      true,
    )}</div><div class="board-risk-level">${
      ctx.riskLevel
    } risk</div><p class="board-narrative">${narrative}</p></div></div>${notes}</div></div>`;
  }

  if (variant === "weekly") {
    const trendDir =
      ctx.trends.length >= 2 &&
      ctx.trends[ctx.trends.length - 1].total !==
        ctx.trends[ctx.trends.length - 2].total
        ? ctx.trends[ctx.trends.length - 1].total <
          ctx.trends[ctx.trends.length - 2].total
          ? "Vulnerability count decreased compared to last month."
          : "Vulnerability count increased compared to last month."
        : null;
    const line = trendDir ? `<p class="narrative-line">${trendDir}</p>` : "";
    return `<div class="section" data-report-aggregate="summary"><div${summaryFilter}><h2>Weekly digest</h2>${filterNote}${line}${notes}${grid}</div></div>`;
  }

  if (variant === "compliance") {
    const processNarrative =
      ctx.avgMttr !== undefined
        ? `Mean time to remediate is ${ctx.avgMttr} days.`
        : "Remediation metrics are being collected.";
    const line = `<p class="narrative-line">${processNarrative} This report provides trend, aging, and full issue inventory for audit and compliance review.</p>`;
    return `<div class="section" data-report-aggregate="summary"><div${summaryFilter}><h2>Executive summary</h2>${filterNote}${line}${notes}${grid}</div></div>`;
  }

  return `<div class="section" data-report-aggregate="summary"><div${summaryFilter}><h2>Executive Summary</h2>${filterNote}${notes}${grid}</div></div>`;
}

function renderSeverityDonut(
  ctx: ReportContext,
  config: Record<string, unknown>,
): string {
  const size = Number(config.size) || 100;
  /* Aggregate widget: always visible, content updated by client-side filter script */
  return `<div class="section" data-report-aggregate="severity-distribution"><div><h2>Severity Distribution</h2><div class="severity-donut-wrap">${svgSeverityDonut(
    ctx.counts,
    ctx.openIssues,
    size,
    getPrimaryColor(ctx),
  )}</div></div></div>`;
}

function renderSeverityBar(ctx: ReportContext): string {
  const primary = getPrimaryColor(ctx);
  const bar =
    ctx.openIssues > 0
      ? ["critical", "high", "medium", "low"]
          .map((s) => {
            const cnt = ctx.counts[s as keyof SeverityCounts];
            return cnt > 0
              ? `<div style="width:${
                  (cnt / ctx.openIssues) * 100
                }%;background:${sevColor(s, primary)}">${cnt}</div>`
              : "";
          })
          .join("")
      : '<div style="width:100%;background:#e2e8f0;color:#94a3b8">No open issues</div>';
  /* Aggregate widget: always visible, content updated by client-side filter script */
  return `<div class="section" data-report-aggregate="severity-distribution"><div><h2>Severity Distribution</h2><div class="severity-with-donut"><div class="severity-donut-wrap">${svgSeverityDonut(
    ctx.counts,
    ctx.openIssues,
    100,
    primary,
  )}</div><div class="severity-bar-legend"><div class="severity-bar">${bar}</div><div class="severity-legend"><span><span class="dot" style="background:#ef4444"></span> Critical: ${
    ctx.counts.critical
  }</span><span><span class="dot" style="background:#f97316"></span> High: ${
    ctx.counts.high
  }</span><span><span class="dot" style="background:#eab308"></span> Medium: ${
    ctx.counts.medium
  }</span><span><span class="dot" style="background:${primary}"></span> Low: ${
    ctx.counts.low
  }</span></div></div></div></div></div>`;
}

function renderSeverityPills(ctx: ReportContext): string {
  const primary = getPrimaryColor(ctx);
  return `<div class="section severity-compact" data-report-aggregate="severity-pills"><h2>By severity</h2><div class="severity-inline"><span class="sev-pill" data-filter-severity="${filterAttr(
    "critical",
  )}" data-severity="critical" style="background:#ef4444;color:#fff">Critical ${
    ctx.counts.critical
  }</span><span class="sev-pill" data-filter-severity="${filterAttr(
    "high",
  )}" data-severity="high" style="background:#f97316;color:#fff">High ${
    ctx.counts.high
  }</span><span class="sev-pill" data-filter-severity="${filterAttr(
    "medium",
  )}" data-severity="medium" style="background:#eab308;color:#fff">Medium ${
    ctx.counts.medium
  }</span><span class="sev-pill" data-filter-severity="${filterAttr(
    "low",
  )}" data-severity="low" style="background:${primary};color:#fff">Low ${
    ctx.counts.low
  }</span></div></div>`;
}

function renderSourceBar(ctx: ReportContext): string {
  const scanners = ctx.scanners;
  const total = scanners.reduce((s, sc) => s + sc.count, 0);
  const attrs = sectionFilterAttrs(ctx);
  if (total === 0 || scanners.length === 0)
    return `<div class="section" data-report-aggregate="source-distribution"><div${attrs}><h2>Source Distribution</h2><div class="severity-with-donut"><div class="severity-donut-wrap">${svgScannerDonut(
      [],
      0,
      100,
    )}</div><div class="severity-bar-legend"><div class="severity-bar"><div style="width:100%;background:#e2e8f0;color:#94a3b8">No open issues</div></div><div class="severity-legend"><span>No sources</span></div></div></div></div>`;
  const bar =
    scanners
      .slice(0, 8)
      .map((s, i) => {
        const pct = total > 0 ? (s.count / total) * 100 : 0;
        const color = SCANNER_DONUT_COLORS[i % SCANNER_DONUT_COLORS.length];
        return pct > 0
          ? `<div style="width:${pct}%;background:${color}">${s.count}</div>`
          : "";
      })
      .join("") ||
    '<div style="width:100%;background:#e2e8f0;color:#94a3b8">No open issues</div>';
  const legend = scanners
    .slice(0, 8)
    .map(
      (s, i) =>
        `<span><span class="dot" style="background:${
          SCANNER_DONUT_COLORS[i % SCANNER_DONUT_COLORS.length]
        }"></span> ${displaySourceName(s.scanner) || s.scanner}: ${
          s.count
        }</span>`,
    )
    .join("");
  return `<div class="section" data-report-aggregate="source-distribution"><div${attrs}><h2>Source Distribution</h2><div class="severity-with-donut"><div class="severity-donut-wrap">${svgScannerDonut(
    scanners,
    total,
    100,
  )}</div><div class="severity-bar-legend"><div class="severity-bar">${bar}</div><div class="severity-legend">${legend}</div></div></div></div></div>`;
}

function renderRiskGauge(
  ctx: ReportContext,
  config: Record<string, unknown>,
): string {
  const size = Number(config.size) || 120;
  const attrs = sectionFilterAttrs(ctx);
  const tooltipAttr = ` data-tooltip="${ORA_INFO_TITLE.replace(
    /"/g,
    "&quot;",
  )}"`;
  return `<div class="section" data-report-aggregate="risk-gauge" data-gauge-size="${size}"><div${attrs}><h2${tooltipAttr}>Risk score</h2><div class="board-hero-viz">${svgRiskGauge(
    ctx.riskScore,
    size,
  )}</div></div></div>`;
}

function renderTrendSparkline(
  ctx: ReportContext,
  config: Record<string, unknown>,
): string {
  if (ctx.trends.length === 0) return "";
  const w = Number(config.width) || 280;
  const h = Number(config.height) || 56;
  const attrs = sectionFilterAttrs(ctx);
  return `<div class="section"><div${attrs}><h2>12-Month Trend</h2><div class="viz-trend-wrap">${svgTrendSparkline(
    ctx.trends,
    w,
    h,
    getPrimaryColor(ctx),
  )}</div></div></div>`;
}

function renderTrendTable(
  ctx: ReportContext,
  config: Record<string, unknown>,
): string {
  if (ctx.trends.length === 0) return "";
  const limit = Number(config.limit) ?? 999;
  const trends = ctx.trends.slice(0, limit);
  const rows = trends
    .map((t) => {
      const sevs: string[] = [];
      if (t.critical > 0) sevs.push("critical");
      if (t.high > 0) sevs.push("high");
      if (t.medium > 0) sevs.push("medium");
      if (t.low > 0) sevs.push("low");
      const sevAttr =
        sevs.length > 0
          ? ` data-filter-severity="${filterAttr(sevs.join(" "))}"`
          : "";
      return `<tr${sevAttr}><td>${t.date}</td><td class="text-right mono ${
        t.critical > 0 ? "critical-val" : ""
      }">${t.critical}</td><td class="text-right mono ${
        t.high > 0 ? "high-val" : ""
      }">${t.high}</td><td class="text-right mono ${
        t.medium > 0 ? "medium-val" : ""
      }">${t.medium}</td><td class="text-right mono ${
        t.low > 0 ? "low-val" : ""
      }">${t.low}</td><td class="text-right mono" style="font-weight:600">${
        t.total
      }</td></tr>`;
    })
    .join("");
  const attrs = sectionFilterAttrs(ctx);
  const totalNote =
    ctx.trends.length > trends.length
      ? ` (${trends.length} of ${ctx.trends.length})`
      : "";
  return `<div class="section"><div${attrs}><h2>12-Month Trend${totalNote}</h2><table><thead><tr><th>Month</th><th class="text-right">Critical</th><th class="text-right">High</th><th class="text-right">Medium</th><th class="text-right">Low</th><th class="text-right">Total</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
}

function renderAgingBars(
  ctx: ReportContext,
  config: Record<string, unknown>,
): string {
  const maxW = Number(config.maxWidth) || 200;
  const html =
    ctx.aging.length > 0
      ? `<div class="viz-aging-bars">${svgAgingBars(
          ctx.aging,
          maxW,
          getPrimaryColor(ctx),
        )}</div>`
      : "";
  const attrs = sectionFilterAttrs(ctx);
  return `<div class="section"><div${attrs}><h2>Vulnerability Aging</h2>${html}</div></div>`;
}

function renderAgingTable(
  ctx: ReportContext,
  config: Record<string, unknown>,
): string {
  const limit = Number(config.limit) ?? 999;
  const aging = ctx.aging.slice(0, limit);
  const rows = aging
    .map((b) => {
      const sevs: string[] = [];
      if (b.critical > 0) sevs.push("critical");
      if (b.high > 0) sevs.push("high");
      if (b.medium > 0) sevs.push("medium");
      if (b.low > 0) sevs.push("low");
      const sevAttr =
        sevs.length > 0
          ? ` data-filter-severity="${filterAttr(sevs.join(" "))}"`
          : "";
      return `<tr${sevAttr}><td>${b.range}</td><td class="text-right mono ${
        b.critical > 0 ? "critical-val" : ""
      }">${b.critical}</td><td class="text-right mono ${
        b.high > 0 ? "high-val" : ""
      }">${b.high}</td><td class="text-right mono ${
        b.medium > 0 ? "medium-val" : ""
      }">${b.medium}</td><td class="text-right mono ${
        b.low > 0 ? "low-val" : ""
      }">${b.low}</td><td class="text-right mono" style="font-weight:600">${
        b.critical + b.high + b.medium + b.low
      }</td></tr>`;
    })
    .join("");
  const totalNote =
    ctx.aging.length > aging.length
      ? ` (${aging.length} of ${ctx.aging.length})`
      : "";
  return `<div class="section"><h2>Vulnerability Aging${totalNote}</h2><table><thead><tr><th>Age</th><th class="text-right">Critical</th><th class="text-right">High</th><th class="text-right">Medium</th><th class="text-right">Low</th><th class="text-right">Total</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

function renderMttrBars(ctx: ReportContext): string {
  if (ctx.mttr.length === 0) return "";
  const primary = getPrimaryColor(ctx);
  const maxDays = Math.max(...ctx.mttr.map((m) => m.avgDays), 1);
  const bars = ctx.mttr
    .map((m) => {
      const w = Math.max(4, (m.avgDays / maxDays) * 120);
      const s = m.severity.toLowerCase();
      return `<div class="mttr-bar-row" data-filter-severity="${filterAttr(
        s,
      )}"><span class="badge ${sev(s)}">${
        m.severity
      }</span><div class="mttr-bar-track"><div class="mttr-bar-fill" style="width:${w}px;background:${sevColor(
        m.severity,
        primary,
      )}"></div></div><span class="mttr-bar-num">${m.avgDays}d</span></div>`;
    })
    .join("");
  const sevAttrs = ctx.mttr
    .map((m) => m.severity.toLowerCase())
    .map((s) => filterAttr(s))
    .join(" ");
  const mttrFilter = sevAttrs ? ` data-filter-severity="${sevAttrs}"` : "";
  return `<div class="section"><div${mttrFilter}><h2>Mean Time to Remediate</h2><div class="viz-mttr-bars">${bars}</div></div></div>`;
}

function renderMttrTable(ctx: ReportContext): string {
  if (ctx.mttr.length === 0) return "";
  const rows = ctx.mttr
    .map((m) => {
      const s = m.severity.toLowerCase();
      return `<tr data-filter-severity="${filterAttr(
        s,
      )}"><td><span class="badge ${sev(s)}">${
        m.severity
      }</span></td><td class="text-right mono">${
        m.avgDays
      }</td><td class="text-right mono">${
        m.medianDays
      }</td><td class="text-right mono">${m.count}</td></tr>`;
    })
    .join("");
  const sevAttrs = ctx.mttr
    .map((m) => m.severity.toLowerCase())
    .map((s) => filterAttr(s))
    .join(" ");
  const mttrFilter = sevAttrs ? ` data-filter-severity="${sevAttrs}"` : "";
  return `<div class="section"><div${mttrFilter}><h2>Mean Time to Remediate</h2><table><thead><tr><th>Severity</th><th class="text-right">Avg (days)</th><th class="text-right">Median (days)</th><th class="text-right">Resolved</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
}

function renderRepoBars(
  ctx: ReportContext,
  config: Record<string, unknown>,
): string {
  const maxRepos = Number(config.maxRepos) || 8;
  const repos = ctx.repoRisk.slice(0, maxRepos);
  if (repos.length === 0) return "";
  const attrs = sectionFilterAttrs(ctx);
  return `<div class="section"><div${attrs}><h2>Repository Risk</h2><div class="viz-repo-bars">${svgRepoRiskBars(
    repos,
    100,
    maxRepos,
  )}</div></div></div>`;
}

function renderRepoTable(
  ctx: ReportContext,
  config: Record<string, unknown>,
): string {
  const limit = Number(config.limit) ?? 25;
  const repos = ctx.repoRisk.slice(0, limit);
  if (repos.length === 0) return "";
  const rows = repos
    .map((repo) => {
      const sevs: string[] = [];
      if (repo.critical > 0) sevs.push("critical");
      if (repo.high > 0) sevs.push("high");
      if (repo.medium > 0) sevs.push("medium");
      if (repo.low > 0) sevs.push("low");
      const sevAttr =
        sevs.length > 0
          ? ` data-filter-severity="${filterAttr(sevs.join(" "))}"`
          : "";
      return `<tr data-filter-repo="${filterAttr(
        repo.repo,
      )}" data-filter-asset-type="${filterAttr(
        "Code",
      )}"${sevAttr}><td class="mono">${
        repo.repo
      }</td><td class="text-right mono ${
        repo.critical > 0 ? "critical-val" : ""
      }">${repo.critical || "-"}</td><td class="text-right mono ${
        repo.high > 0 ? "high-val" : ""
      }">${repo.high || "-"}</td><td class="text-right mono ${
        repo.medium > 0 ? "medium-val" : ""
      }">${repo.medium || "-"}</td><td class="text-right mono ${
        repo.low > 0 ? "low-val" : ""
      }">${
        repo.low || "-"
      }</td><td class="text-right mono" style="font-weight:600">${
        repo.score
      }</td></tr>`;
    })
    .join("");
  const attrs = sectionFilterAttrs(ctx);
  return `<div class="section"><div${attrs} data-report-aggregate="repo-risk" data-limit="${limit}"><h2>Repository Risk Ranking</h2><table><thead><tr><th>Repository</th><th class="text-right">Critical</th><th class="text-right">High</th><th class="text-right">Medium</th><th class="text-right">Low</th><th class="text-right">Risk Score</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
}

function renderTopVulnsTable(
  ctx: ReportContext,
  config: Record<string, unknown>,
): string {
  const limit = Number(config.limit) ?? 25;
  const vulns = ctx.topVulns.slice(0, limit);
  const issueById = (id: number) =>
    ctx.filteredIssues.find((i) => i.issue_id === id);
  const repoNames = ctx.repoRisk.map((r) => r.repo);
  const containerNames = ctx.containerRisk.map((c) => c.repo);
  const vmNames = ctx.vmNames ?? [];
  const packageNames = ctx.packageNames ?? [];
  const rows = vulns
    .map((v) => {
      const issue = issueById(v.id);
      const groupId = issue?.issue_group_id ?? 0;
      const tasks = ctx.tasksByGroupId?.[groupId];
      const trackingCell =
        tasks && tasks.length > 0
          ? formatTaskLinks(tasks, ctx.external) ||
            '<span style="color:#22c55e">Tracked</span>'
          : v.hasTask
            ? '<span style="color:#22c55e">Tracked</span>'
            : '<span style="color:#94a3b8">-</span>';
      const titleCell = v.title
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
      const containerMatch = findMatchingContainer(v.repo, ctx.containerRisk);
      const containerAttr = containerMatch
        ? ` data-filter-container="${filterAttr(containerMatch)}"`
        : "";
      const assetType = getAssetTypeForIssue(
        v.repo,
        repoNames,
        containerNames,
        vmNames,
        packageNames,
      );
      const assetTypeAttr = ` data-filter-asset-type="${filterAttr(
        assetType,
      )}"`;
      const scannerAttr = ` data-filter-scanner="${filterAttr(
        displaySourceName(issue?.scanner_type) ||
          issue?.scanner_type ||
          "Unknown",
      )}"`;
      return `<tr data-filter-severity="${filterAttr(
        v.severity?.toLowerCase(),
      )}" data-filter-repo="${filterAttr(
        v.repo,
      )}" data-filter-branch="${filterAttr(
        issue?.branch,
      )}"${assetTypeAttr}${containerAttr}${scannerAttr}><td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${titleCell}</td><td><span class="badge ${sev(
        v.severity,
      )}">${v.severity}</span></td><td class="mono">${
        v.cve
      }</td><td class="mono">${v.repo}</td><td class="text-right mono ${
        v.age > 90 ? "critical-val" : v.age > 30 ? "high-val" : ""
      }">${v.age}d</td><td>${trackingCell}</td></tr>`;
    })
    .join("");
  const attrs = sectionFilterAttrs(ctx);
  return `<div class="section"><div${attrs}><h2>Top Vulnerabilities</h2><table><thead><tr><th>Vulnerability</th><th>Severity</th><th>CVE</th><th>Repository</th><th class="text-right">Age</th><th>Tracking</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
}

function renderTopVulnsList(
  ctx: ReportContext,
  config: Record<string, unknown>,
): string {
  const limit = Number(config.limit) ?? 5;
  const vulns = ctx.topVulns.slice(0, limit);
  const issueById = (id: number) =>
    ctx.filteredIssues.find((i) => i.issue_id === id);
  const repoNames = ctx.repoRisk.map((r) => r.repo);
  const containerNames = ctx.containerRisk.map((c) => c.repo);
  const vmNames = ctx.vmNames ?? [];
  const packageNames = ctx.packageNames ?? [];
  const items = vulns
    .map((v) => {
      const cvss =
        Number.isFinite(v.score) && v.score > 0
          ? ` · CVSS ${v.score.toFixed(1)}`
          : "";
      const issue = issueById(v.id);
      const titlePart = v.title
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
      const containerMatch = findMatchingContainer(v.repo, ctx.containerRisk);
      const containerAttr = containerMatch
        ? ` data-filter-container="${filterAttr(containerMatch)}"`
        : "";
      const assetType = getAssetTypeForIssue(
        v.repo,
        repoNames,
        containerNames,
        vmNames,
        packageNames,
      );
      const assetTypeAttr = ` data-filter-asset-type="${filterAttr(
        assetType,
      )}"`;
      const scannerAttr = ` data-filter-scanner="${filterAttr(
        displaySourceName(issue?.scanner_type) ||
          issue?.scanner_type ||
          "Unknown",
      )}"`;
      return `<li data-filter-severity="${filterAttr(
        v.severity?.toLowerCase(),
      )}" data-filter-repo="${filterAttr(
        v.repo,
      )}" data-filter-branch="${filterAttr(
        issue?.branch,
      )}"${assetTypeAttr}${containerAttr}${scannerAttr}><span class="badge ${sev(
        v.severity,
      )}">${v.severity}</span> ${titlePart} <span class="findings-meta">${
        v.cve !== "N/A" ? v.cve : ""
      }${cvss} · ${v.repo}</span></li>`;
    })
    .join("");
  const attrs = sectionFilterAttrs(ctx);
  return `<div class="section"><div${attrs}><h2>Key findings</h2><ul class="findings-list">${items}</ul></div></div>`;
}

function cveLink(cve: string): string {
  if (!cve || cve === "N/A") return cve;
  const normalized = cve.toUpperCase().startsWith("CVE-") ? cve : `CVE-${cve}`;
  return `<a href="https://nvd.nist.gov/vuln/detail/${normalized}" target="_blank" rel="noopener noreferrer" class="cve-link">${cve}</a>`;
}

function normalizeCveKey(cve: string): string {
  if (!cve || cve === "N/A") return "";
  return `CVE-${String(cve)
    .replace(/^CVE-?/i, "")
    .toUpperCase()}`;
}

function renderTopVulnsAdvisory(
  ctx: ReportContext,
  config: Record<string, unknown>,
): string {
  const limit = Number(config.limit) ?? 30;
  const vulns = ctx.topVulns.slice(0, limit);
  const issueById = (id: number) =>
    ctx.filteredIssues.find((i) => i.issue_id === id);
  const repoNames = ctx.repoRisk.map((r) => r.repo);
  const containerNames = ctx.containerRisk.map((c) => c.repo);
  const vmNames = ctx.vmNames ?? [];
  const packageNames = ctx.packageNames ?? [];
  const cards = vulns
    .map((v) => {
      const issue = issueById(v.id);
      const desc = issue?.description || issue?.title || v.title;
      const fixed = issue?.fixed_version
        ? `Update to <code>${issue.fixed_version}</code> or apply vendor patch.`
        : "No fix version reported; apply mitigation or monitor vendor advisory.";
      const cwe = issue?.cwe_id
        ? `CWE-${String(issue.cwe_id).replace("CWE-", "")}`
        : "";
      const cveDisplay =
        v.cve && v.cve !== "N/A" ? cveLink(v.cve) : v.cve || "—";
      const pkgRow =
        issue?.affected_package || issue?.affected_version
          ? `<div class="advisory-row"><strong>Affected</strong> ${
              issue?.affected_package || ""
            } ${issue?.affected_version || ""}</div>`
          : "";
      const tasks = ctx.tasksByGroupId?.[issue?.issue_group_id ?? 0];
      const tasksRow =
        tasks && tasks.length > 0
          ? `<div class="advisory-row"><strong>Linked tasks</strong> ${formatTaskLinks(
              tasks,
              ctx.external,
            )}</div>`
          : "";
      const titlePart = v.title
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
      const linkRow = "";
      const cveKey = normalizeCveKey(v.cve);
      const cveDetails = cveKey ? ctx.cveDetailsByCveId?.[cveKey] : undefined;
      const epssRow =
        cveDetails && (cveDetails.epss_score !== undefined || cveDetails.in_kev)
          ? `<div class="advisory-row"><strong>Risk</strong>${
              cveDetails.epss_score !== undefined
                ? ` EPSS ${(cveDetails.epss_score * 100).toFixed(2)}%`
                : ""
            }${
              cveDetails.in_kev
                ? ' · <span class="badge badge-critical" title="In CISA Known Exploited Vulnerabilities catalog">KEV</span>'
                : ""
            }</div>`
          : "";
      const containerMatch = findMatchingContainer(v.repo, ctx.containerRisk);
      const containerAttr = containerMatch
        ? ` data-filter-container="${filterAttr(containerMatch)}"`
        : "";
      const assetType = getAssetTypeForIssue(
        v.repo,
        repoNames,
        containerNames,
        vmNames,
        packageNames,
      );
      const assetTypeAttr = ` data-filter-asset-type="${filterAttr(
        assetType,
      )}"`;
      const scannerAttr = ` data-filter-scanner="${filterAttr(
        displaySourceName(issue?.scanner_type) ||
          issue?.scanner_type ||
          "Unknown",
      )}"`;
      return `<div class="advisory-card report-filterable" data-filter-severity="${filterAttr(
        v.severity?.toLowerCase(),
      )}" data-filter-repo="${filterAttr(
        v.repo,
      )}" data-filter-branch="${filterAttr(
        issue?.branch,
      )}"${assetTypeAttr}${containerAttr}${scannerAttr}><div class="advisory-header"><span class="badge ${sev(
        v.severity,
      )}">${
        v.severity
      }</span><span class="advisory-title">${titlePart}</span></div><div class="advisory-row"><strong>ID / CVE</strong> ${cveDisplay}${
        cwe ? ` · ${cwe}` : ""
      }</div><div class="advisory-row"><strong>Description</strong> ${desc}</div><div class="advisory-row"><strong>Impact</strong> ${
        v.severity === "critical" || v.severity === "high"
          ? "High impact; may allow unauthorized access or compromise."
          : "Medium or low impact depending on context."
      }</div><div class="advisory-row"><strong>CVSS</strong> ${
        Number.isFinite(v.score) && v.score > 0 ? v.score.toFixed(1) : "—"
      } ${
        v.repo ? ` · Affected: ${v.repo}` : ""
      }</div>${epssRow}${pkgRow}${tasksRow}${linkRow}<div class="advisory-row"><strong>Resolution</strong> ${fixed}</div></div>`;
    })
    .join("");
  const attrs = sectionFilterAttrs(ctx);
  return `<div class="section"><div${attrs}><h2>Findings (advisory format)</h2><p class="narrative-line">Product/workspace: <strong>${ctx.workspace}</strong>. Below: description, impact, affected versions, and resolution for each finding. CVE links open NVD details.</p>${cards}</div></div>`;
}

function renderScannerTable(
  ctx: ReportContext,
  config: Record<string, unknown>,
): string {
  if (ctx.scanners.length === 0) return "";
  const limit = Number(config.limit) ?? 999;
  const scanners = ctx.scanners.slice(0, limit);
  const rows = scanners
    .map((s) => {
      const sevs: string[] = [];
      if (s.critical > 0) sevs.push("critical");
      if (s.high > 0) sevs.push("high");
      if (s.medium > 0) sevs.push("medium");
      if (s.low > 0) sevs.push("low");
      const sevAttr =
        sevs.length > 0
          ? ` data-filter-severity="${filterAttr(sevs.join(" "))}"`
          : "";
      return `<tr${sevAttr} data-filter-scanner="${filterAttr(
        displaySourceName(s.scanner) || s.scanner || "Unknown",
      )}"><td class="mono">${
        displaySourceName(s.scanner) || s.scanner
      }</td><td class="text-right mono" style="font-weight:600">${
        s.count
      }</td><td class="text-right mono ${
        s.critical > 0 ? "critical-val" : ""
      }">${s.critical || "-"}</td><td class="text-right mono ${
        s.high > 0 ? "high-val" : ""
      }">${s.high || "-"}</td><td class="text-right mono ${
        s.medium > 0 ? "medium-val" : ""
      }">${s.medium || "-"}</td><td class="text-right mono ${
        s.low > 0 ? "low-val" : ""
      }">${s.low || "-"}</td></tr>`;
    })
    .join("");
  const attrs = sectionFilterAttrs(ctx);
  const totalNote =
    ctx.scanners.length > scanners.length
      ? ` (${scanners.length} of ${ctx.scanners.length})`
      : "";
  return `<div class="section"><div${attrs}><h2>Scanner Breakdown${totalNote}</h2><table><thead><tr><th>Scanner</th><th class="text-right">Issues</th><th class="text-right">Critical</th><th class="text-right">High</th><th class="text-right">Medium</th><th class="text-right">Low</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
}

function renderScannerDonut(
  ctx: ReportContext,
  config: Record<string, unknown>,
): string {
  if (ctx.scanners.length === 0) return "";
  const total = ctx.scanners.reduce((s, sc) => s + sc.count, 0);
  const size = Number(config.size) || 100;
  const legend = ctx.scanners
    .slice(0, 8)
    .map(
      (s, i) =>
        `<span><span class="dot" style="background:${
          SCANNER_DONUT_COLORS[i % SCANNER_DONUT_COLORS.length]
        }"></span> ${displaySourceName(s.scanner) || s.scanner} (${
          s.count
        })</span>`,
    )
    .join("");
  const attrs = sectionFilterAttrs(ctx);
  return `<div class="section"><div${attrs}><h2>Findings by Scanner</h2><div class="severity-with-donut"><div class="severity-donut-wrap">${svgScannerDonut(
    ctx.scanners,
    total,
    size,
  )}</div><div class="severity-bar-legend severity-legend">${legend}</div></div></div></div>`;
}

function renderTrendStacked(
  ctx: ReportContext,
  config: Record<string, unknown>,
): string {
  const periodDays =
    (ctx.effectivePeriodDays ?? Number(config.periodDays)) || 90;
  const countMode = ctx.countMode ?? "groups";
  const trendIssues = ctx.issuesForTrend ?? ctx.filteredIssues;
  // When date range is "All" (no filter), use 12-month trend like overview; otherwise use last N days
  const trendsRaw =
    ctx.dateRange == null
      ? computeTrendData(trendIssues, countMode)
      : computeTrendDataLastDays(trendIssues, periodDays, countMode);
  const trends = trendsRaw.filter((t) => t.total > 0);
  const w = Number(config.width) || 560;
  const h = Number(config.height) || 160;
  const content =
    trends.length > 0
      ? svgTrendStacked(trends, w, h)
      : `<div class="viz-trend-empty" style="display:flex;align-items:center;justify-content:center;min-height:140px;color:#64748b;font-size:14px">No findings in selected period</div>`;
  const trendFilter = "";

  const metrics = computeTrendMetrics(trendIssues, countMode);
  // Use ctx.openIssues for "Current open" so it matches the report's OPEN count (avoid 1383 vs 1375 confusion)
  const currentOpen = ctx.openIssues;
  const openPct =
    metrics.openOneWeekAgo === 0
      ? currentOpen > 0
        ? 100
        : 0
      : Math.round(
          ((currentOpen - metrics.openOneWeekAgo) / metrics.openOneWeekAgo) *
            100,
        );
  const resolvedPct =
    metrics.resolvedLastWeek === 0
      ? metrics.resolvedThisWeek > 0
        ? 100
        : 0
      : Math.round(
          ((metrics.resolvedThisWeek - metrics.resolvedLastWeek) /
            metrics.resolvedLastWeek) *
            100,
        );
  const newPct =
    metrics.newLastWeek === 0
      ? metrics.newThisWeek > 0
        ? 100
        : 0
      : Math.round(
          ((metrics.newThisWeek - metrics.newLastWeek) / metrics.newLastWeek) *
            100,
        );

  const openPctText =
    openPct > 0 ? `+${openPct}%` : openPct < 0 ? `${openPct}%` : "0%";
  const resolvedPctText =
    resolvedPct > 0
      ? `+${resolvedPct}%`
      : resolvedPct < 0
        ? `${resolvedPct}%`
        : "0%";
  const newPctText =
    newPct > 0 ? `+${newPct}%` : newPct < 0 ? `${newPct}%` : "0%";

  const openPctColor =
    currentOpen <= metrics.openOneWeekAgo ? "#22c55e" : "#ef4444";
  const resolvedPctColor =
    metrics.resolvedThisWeek >= metrics.resolvedLastWeek
      ? "#22c55e"
      : "#ef4444";
  const newPctColor =
    metrics.newThisWeek <= metrics.newLastWeek ? "#22c55e" : "#ef4444";

  const topBar = `<div class="kpi-grid trend-stacked-topbar" style="grid-template-columns: repeat(3, 1fr); margin-bottom: 16px;">
    <div class="kpi-card"><div class="label">Current open issues</div><div class="value">${currentOpen.toLocaleString()}</div><div class="detail">vs ${metrics.openOneWeekAgo.toLocaleString()} one week ago</div><div class="kpi-trend" style="color:${openPctColor}">${openPctText}</div></div>
    <div class="kpi-card"><div class="label">Resolved this week</div><div class="value">${metrics.resolvedThisWeek.toLocaleString()}</div><div class="detail">vs ${metrics.resolvedLastWeek.toLocaleString()} last week</div><div class="kpi-trend" style="color:${resolvedPctColor}">${resolvedPctText}</div></div>
    <div class="kpi-card"><div class="label">New issues this week</div><div class="value">${metrics.newThisWeek.toLocaleString()}</div><div class="detail">vs ${metrics.newLastWeek.toLocaleString()} last week</div><div class="kpi-trend" style="color:${newPctColor}">${newPctText}</div></div>
  </div>`;

  const trendFilters = buildTrendFilterPills(ctx, periodDays, countMode);
  return `<div class="section trend-stacked-section" data-report-aggregate="trend-stacked" data-trend-period-days="${periodDays}" data-trend-count-mode="${countMode}" data-trend-granularity="weekly"><div${trendFilter}><h2>Severity trend</h2>${trendFilters}${topBar}<div class="viz-trend-wrap viz-trend-stacked-wrap" style="aspect-ratio: ${w}/${h};">${content}</div></div></div>`;
}

function renderOpenVsClosed(ctx: ReportContext): string {
  const open = ctx.openIssues;
  const closed = ctx.totalIssues - open;
  const total = ctx.totalIssues;
  const openPct = total > 0 ? Math.round((open / total) * 100) : 0;
  const closedPct = total > 0 ? Math.round((closed / total) * 100) : 0;
  const attrs = sectionFilterAttrs(ctx);
  return `<div class="section"><div${attrs}><h2>Remediation Progress</h2><div class="kpi-grid" style="grid-template-columns: repeat(2, 1fr);"><div class="kpi-card"><div class="label">Open</div><div class="value" style="color:#f97316">${open}</div><div class="detail">${openPct}% of total</div></div><div class="kpi-card"><div class="label">Closed</div><div class="value" style="color:#22c55e">${closed}</div><div class="detail">${closedPct}% of total</div></div></div></div></div>`;
}

function renderCriticalHighKpi(ctx: ReportContext): string {
  const criticalHigh = ctx.counts.critical + ctx.counts.high;
  const attrs = sectionFilterAttrs(ctx);
  return `<div class="section"><div${attrs}><h2>Priority Findings</h2><div class="kpi-grid" style="grid-template-columns: 1fr;"><div class="kpi-card"><div class="label">Critical &amp; High</div><div class="value" style="color:${
    criticalHigh > 0 ? "#f97316" : "#22c55e"
  }">${criticalHigh}</div><div class="detail">${
    criticalHigh > 0 ? "Requires attention" : "None open"
  }</div></div></div></div></div>`;
}

const SEVERITY_SORT_ORDER: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

function renderIssueList(
  ctx: ReportContext,
  config: Record<string, unknown>,
): string {
  const limit = Number(config.limit) ?? 100;
  const issues = [...ctx.filteredIssues]
    .sort((a, b) => {
      const aOpen = isOpen(a) ? 1 : 0;
      const bOpen = isOpen(b) ? 1 : 0;
      if (aOpen !== bOpen) return bOpen - aOpen;
      return (
        (SEVERITY_SORT_ORDER[(b.severity ?? "").toLowerCase()] ?? 0) -
        (SEVERITY_SORT_ORDER[(a.severity ?? "").toLowerCase()] ?? 0)
      );
    })
    .slice(0, limit);
  const repoNames = ctx.repoRisk.map((r) => r.repo);
  const containerNames = ctx.containerRisk.map((c) => c.repo);
  const vmNames = ctx.vmNames ?? [];
  const packageNames = ctx.packageNames ?? [];
  const rows = issues
    .map((i) => {
      const age = Math.max(
        0,
        Math.round(
          (Date.now() - new Date(i.first_detected_at).getTime()) / 86400000,
        ),
      );
      const s = (i.severity ?? "").toLowerCase();
      const tasks = ctx.tasksByGroupId?.[i.issue_group_id ?? 0];
      const tasksCell =
        tasks && tasks.length > 0 ? formatTaskLinks(tasks, ctx.external) : "-";
      const idCell = String(i.issue_id);
      const titleCell = i.title
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
      const containerMatch = findMatchingContainer(
        i.repository,
        ctx.containerRisk,
      );
      const containerAttr = containerMatch
        ? ` data-filter-container="${filterAttr(containerMatch)}"`
        : "";
      const sortStatus = isOpen(i) ? "open" : "closed";
      const source = displaySourceName(i.scanner_type) || "-";
      const assetType = getAssetTypeForIssue(
        i.repository,
        repoNames,
        containerNames,
        vmNames,
        packageNames,
      );
      const asset = i.repository || "-";
      const assetTypeAttr = ` data-filter-asset-type="${filterAttr(
        assetType,
      )}"`;
      const scannerAttr = ` data-filter-scanner="${filterAttr(source)}"`;
      return `<tr data-filter-severity="${filterAttr(
        s,
      )}" data-filter-repo="${filterAttr(
        i.repository,
      )}" data-filter-branch="${filterAttr(
        i.branch,
      )}" data-sort-status="${sortStatus}"${assetTypeAttr}${containerAttr}${scannerAttr}><td class="mono">${idCell}</td><td>${titleCell}</td><td><span class="badge ${sev(
        s,
      )}">${
        i.severity
      }</span></td><td class="mono">${source}</td><td>${assetType}</td><td class="mono">${asset}</td><td class="text-right mono">${
        Number.isFinite(age) ? `${age}d` : "-"
      }</td><td>${i.status}</td><td>${tasksCell}</td></tr>`;
    })
    .join("");
  const attrs = sectionFilterAttrs(ctx);
  return `<div class="section"><div${attrs}><h2>Issue Inventory (${issues.length} of ${ctx.filteredIssues.length})</h2><table class="issue-inventory-table"><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Source</th><th>Asset Type</th><th>Asset</th><th class="text-right">Age</th><th class="sortable sortable-status" data-sort-col="status">Status</th><th>Tasks</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
}

function renderContainerBars(
  ctx: ReportContext,
  config: Record<string, unknown>,
): string {
  const maxContainers = Number(config.maxContainers) ?? 8;
  const containers = ctx.containerRisk.slice(0, maxContainers);
  const attrs = sectionFilterAttrs(ctx);
  if (containers.length === 0)
    return `<div class="section"><div${attrs}><h2>Container Risk</h2><p class="activity-empty">No container repositories with issues.</p></div></div>`;
  return `<div class="section"><div${attrs}><h2>Container Risk</h2><div class="viz-repo-bars">${svgContainerRiskBars(
    containers,
    100,
    maxContainers,
  )}</div></div></div>`;
}

function renderContainerTable(
  ctx: ReportContext,
  config: Record<string, unknown>,
): string {
  const limit = Number(config.limit) ?? 25;
  const containers = ctx.containerRisk.slice(0, limit);
  if (containers.length === 0)
    return `<div class="section"><div data-report-aggregate="container-risk" data-limit="${limit}"><h2>Container Risk Ranking</h2><p class="activity-empty">No container repositories with issues.</p></div></div>`;
  const rows = containers
    .map((c) => {
      const sevs: string[] = [];
      if (c.critical > 0) sevs.push("critical");
      if (c.high > 0) sevs.push("high");
      if (c.medium > 0) sevs.push("medium");
      if (c.low > 0) sevs.push("low");
      const sevAttr =
        sevs.length > 0
          ? ` data-filter-severity="${filterAttr(sevs.join(" "))}"`
          : "";
      const containerAttr = ` data-filter-container="${filterAttr(c.repo)}"`;
      return `<tr data-filter-repo="${filterAttr(
        c.repo,
      )}" data-filter-asset-type="${filterAttr(
        "Container",
      )}"${containerAttr}${sevAttr}><td class="mono">${
        c.repo
      }</td><td class="text-right mono ${
        c.critical > 0 ? "critical-val" : ""
      }">${c.critical || "-"}</td><td class="text-right mono ${
        c.high > 0 ? "high-val" : ""
      }">${c.high || "-"}</td><td class="text-right mono ${
        c.medium > 0 ? "medium-val" : ""
      }">${c.medium || "-"}</td><td class="text-right mono ${
        c.low > 0 ? "low-val" : ""
      }">${
        c.low || "-"
      }</td><td class="text-right mono" style="font-weight:600">${
        c.score
      }</td></tr>`;
    })
    .join("");
  const attrs = sectionFilterAttrs(ctx);
  return `<div class="section"><div${attrs} data-report-aggregate="container-risk" data-limit="${limit}"><h2>Container Risk Ranking</h2><table><thead><tr><th>Container</th><th class="text-right">Critical</th><th class="text-right">High</th><th class="text-right">Medium</th><th class="text-right">Low</th><th class="text-right">Risk Score</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
}

function renderAssetMixDonut(
  ctx: ReportContext,
  config: Record<string, unknown>,
): string {
  const mix = ctx.assetMix;
  const total =
    mix.code + mix.container + mix.vm + (mix.package ?? 0) + mix.other;
  const attrs = sectionFilterAttrs(ctx);
  const size = Number(config.size) ?? 100;
  const primary = getPrimaryColor(ctx);
  if (total === 0)
    return `<div class="section" data-report-aggregate="asset-mix" data-asset-mix-size="${size}"><div${attrs}><h2>Issues by Asset Type</h2><div class="asset-mix-body"><p class="activity-empty">No open issues to categorize.</p></div></div></div>`;
  const categories = [
    { count: mix.code, label: "Code" },
    { count: mix.container, label: "Container" },
    { count: mix.vm, label: "VM" },
    { count: mix.package ?? 0, label: "Package" },
    { count: mix.other, label: "Other" },
  ].filter((s) => s.count > 0);
  if (categories.length === 1) {
    return `<div class="section" data-report-aggregate="asset-mix" data-asset-mix-size="${size}"><div${attrs}><h2>Issues by Asset Type</h2><div class="asset-mix-body"><p class="narrative-line">All ${total} issues are from ${categories[0].label.toLowerCase()} repositories.</p></div></div></div>`;
  }
  const legend = [
    { count: mix.code, label: "Code", color: primary },
    { count: mix.container, label: "Container", color: "#8b5cf6" },
    { count: mix.vm, label: "VM", color: "#ec4899" },
    { count: mix.package ?? 0, label: "Package", color: "#22c55e" },
    { count: mix.other, label: "Other", color: "#94a3b8" },
  ]
    .filter((s) => s.count > 0)
    .map(
      (s) =>
        `<span><span class="dot" style="background:${s.color}"></span> ${s.label} (${s.count})</span>`,
    )
    .join("");
  return `<div class="section" data-report-aggregate="asset-mix" data-asset-mix-size="${size}"><div${attrs}><h2>Issues by Asset Type</h2><div class="asset-mix-body"><div class="severity-with-donut"><div class="severity-donut-wrap">${svgAssetMixDonut(
    mix,
    total,
    size,
    getPrimaryColor(ctx),
  )}</div><div class="severity-bar-legend severity-legend">${legend}</div></div></div></div></div>`;
}

function renderTeamTable(
  ctx: ReportContext,
  config: Record<string, unknown>,
): string {
  const teams = ctx.teams ?? [];
  const limit = Number(config.limit) ?? 999;
  const limited = teams.slice(0, limit);
  const attrs = sectionFilterAttrs(ctx);
  if (teams.length === 0)
    return `<div class="section"><div${attrs}><h2>Teams</h2><p class="activity-empty">No teams configured.</p></div></div>`;
  const rows = limited
    .map((t) => `<tr><td class="mono">${t.name}</td></tr>`)
    .join("");
  const totalNote =
    teams.length > limited.length
      ? ` (${limited.length} of ${teams.length})`
      : "";
  return `<div class="section"><div${attrs}><h2>Teams${totalNote}</h2><table><thead><tr><th>Team</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
}

function renderActivityTimeline(
  ctx: ReportContext,
  config: Record<string, unknown>,
): string {
  const log = ctx.activityLog ?? [];
  const limit = Number(config.limit) ?? 20;
  const items = log.slice(0, limit);
  const attrs = sectionFilterAttrs(ctx);
  if (items.length === 0) {
    return `<div class="section"><div${attrs}><h2>Activity Timeline</h2><p class="narrative-line">Recent changes (fixed, ignored, severity adjusted, etc.)</p><p class="activity-empty">No recent activity in the log. Activity may be available on paid plans or after workspace activity.</p></div></div>`;
  }
  const rows = items
    .map((a) => {
      const date = new Date(a.timestamp ?? 0).toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
      const target = a.target_name ? ` · ${a.target_name}` : "";
      const user = a.user ? ` · ${a.user}` : "";
      return `<tr><td class="mono" style="font-size:11px;color:#64748b">${date}</td><td>${
        a.action
      }${target}${user}</td>${
        a.details
          ? `<td style="font-size:11px;color:#475569">${a.details}</td>`
          : "<td></td>"
      }</tr>`;
    })
    .join("");
  return `<div class="section"><div${attrs}><h2>Activity Timeline</h2><p class="narrative-line">Recent changes (fixed, ignored, severity adjusted, etc.)</p><table><thead><tr><th>Date</th><th>Action</th><th>Details</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
}

function renderText(
  ctx: ReportContext,
  config: Record<string, unknown>,
): string {
  const content = String(config.content ?? "");
  if (!content.trim()) return "";
  const attrs = sectionFilterAttrs(ctx);
  return `<div class="section"><div${attrs}><div class="narrative-line">${content}</div></div></div>`;
}

function renderComplianceScoreCard(
  ctx: ReportContext,
  config: Record<string, unknown>,
): string {
  const framework = (config.framework as string) || "soc2";
  const labels: Record<string, string> = {
    soc2: "SOC 2",
    nis2: "NIS 2",
    iso27001: "ISO 27001",
  };
  const label = labels[framework] ?? framework.toUpperCase();
  const overview =
    framework === "soc2"
      ? ctx.soc2Compliance
      : framework === "nis2"
        ? ctx.nis2Compliance
        : ctx.iso27001Compliance;
  const attrs = sectionFilterAttrs(ctx);
  if (!overview) {
    return `<div class="section"><div${attrs}><h2>${label} Compliance</h2><p class="activity-empty">Compliance data not available. This feature may require a paid Aikido plan.</p></div></div>`;
  }
  const score = overview.score ?? overview.percentage ?? 0;
  const status =
    overview.status ??
    (score >= 80 ? "Compliant" : score >= 50 ? "Partial" : "At risk");
  const controls =
    overview.controls_total != null
      ? `${overview.controls_passed ?? 0}/${
          overview.controls_total
        } controls passed`
      : "";
  const kpiCards = controls
    ? `<div class="kpi-card"><div class="label">Controls</div><div class="value">${controls}</div></div>`
    : "";
  const statusColor =
    score >= 80 ? "#22c55e" : score >= 50 ? "#eab308" : "#ef4444";
  return `<div class="section"><div${attrs}><h2>${label} Compliance</h2><div class="kpi-grid"><div class="kpi-card"><div class="label">Score</div><div class="value" style="color:${statusColor}">${score}%</div><div class="detail">${status}</div></div>${kpiCards}</div></div></div>`;
}

function renderReachabilityMatrix(ctx: ReportContext): string {
  const rows = ctx.reachabilityMatrix ?? [];
  const attrs = sectionFilterAttrs(ctx);
  if (rows.length === 0)
    return `<div class="section"><div${attrs}><h2>Reachability</h2><p class="activity-empty">No reachability data. Reachability is fetched for top critical/high issues.</p></div></div>`;
  const trs = rows
    .map((r) => {
      const s = r.severity.toLowerCase();
      return `<tr data-filter-severity="${filterAttr(
        s,
      )}"><td><span class="badge ${sev(s)}">${
        r.severity
      }</span></td><td class="text-right mono" style="color:#22c55e">${
        r.exploitable
      }</td><td class="text-right mono" style="color:#64748b">${
        r.notExploitable
      }</td><td class="text-right mono" style="color:#94a3b8">${
        r.unknown
      }</td><td class="text-right mono" style="font-weight:600">${
        r.exploitable + r.notExploitable + r.unknown
      }</td></tr>`;
    })
    .join("");
  return `<div class="section"><div${attrs}><h2>Reachability</h2><p class="narrative-line">Exploitable vs not exploitable by severity (from Aikido reachability analysis)</p><table><thead><tr><th>Severity</th><th class="text-right">Exploitable</th><th class="text-right">Not exploitable</th><th class="text-right">Unknown</th><th class="text-right">Total</th></tr></thead><tbody>${trs}</tbody></table></div></div>`;
}

function renderCiScanFrequency(
  ctx: ReportContext,
  config: Record<string, unknown>,
): string {
  const scans = ctx.ciScans ?? [];
  const periodDays = ctx.effectivePeriodDays ?? Number(config.periodDays) ?? 30;
  const attrs = sectionFilterAttrs(ctx);
  if (scans.length === 0)
    return `<div class="section"><div${attrs}><h2>CI Scan Frequency</h2><p class="activity-empty">No CI scan data. CI scans may require a connected CI/CD integration.</p></div></div>`;
  const cutoff = Date.now() - periodDays * 86400000;
  const recent = scans.filter(
    (s) => new Date(s.created_at ?? s.timestamp ?? 0).getTime() >= cutoff,
  );
  const byDate = new Map<string, { total: number; success: number }>();
  for (const s of recent) {
    const dateStr = (s.created_at ?? s.timestamp ?? "").toString().slice(0, 10);
    if (!dateStr) continue;
    const cur = byDate.get(dateStr) ?? { total: 0, success: 0 };
    cur.total++;
    if (s.success === true) cur.success++;
    byDate.set(dateStr, cur);
  }
  const sorted = [...byDate.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  if (sorted.length === 0)
    return `<div class="section"><div${attrs}><h2>CI Scan Frequency</h2><p class="activity-empty">No CI scans in the last ${periodDays} days.</p></div></div>`;
  const rows = sorted
    .map(
      ([date, d]) =>
        `<tr><td class="mono">${date}</td><td class="text-right mono">${
          d.total
        }</td><td class="text-right mono" style="color:#22c55e">${
          d.success
        }</td><td class="text-right mono" style="color:#64748b">${
          d.total - d.success
        }</td></tr>`,
    )
    .join("");
  return `<div class="section"><div${attrs}><h2>CI Scan Frequency</h2><p class="narrative-line">Scans over the last ${periodDays} days</p><table><thead><tr><th>Date</th><th class="text-right">Total</th><th class="text-right">Success</th><th class="text-right">Failed</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
}

const ABC_INFO_TITLE =
  "Acceptance Baseline Criteria (ABC): Compliance standards for container hardening and vulnerability management. Includes SLA timelines for justification and remediation, max open findings per severity, and CVE age tolerance.";

const ORA_INFO_TITLE =
  "Overall Risk Assessment (ORA): Score 0–100 (higher = riskier). Based on weighted open findings (critical and high contribute most; mitigated findings count half).";

function renderABCCompliance(
  ctx: ReportContext,
  _config: Record<string, unknown>,
): string {
  const abc = ctx.abcCompliance;
  const attrs = sectionFilterAttrs(ctx);
  const tooltipAttr = ` data-tooltip="${ABC_INFO_TITLE.replace(
    /"/g,
    "&quot;",
  )}"`;
  if (!abc) {
    return `<div class="section"><div${attrs}><h2${tooltipAttr}>ABC Compliance</h2><p class="activity-empty">Acceptance Baseline Criteria. No ABC data for this report.</p></div></div>`;
  }
  const statusColor = abc.compliant ? "#22c55e" : "#ef4444";
  const issues: string[] = [];
  if (abc.maxCountExceeded.critical)
    issues.push("Critical max count (1) exceeded");
  if (abc.maxCountExceeded.high) issues.push("High max count (4) exceeded");
  if (abc.justificationOverdue > 0)
    issues.push(`${abc.justificationOverdue} justification(s) overdue`);
  if (abc.remediationOverdue > 0)
    issues.push(`${abc.remediationOverdue} remediation(s) overdue`);
  if (abc.cveAgeExceeded > 0)
    issues.push(`${abc.cveAgeExceeded} CVE age tolerance exceeded`);
  const issuesHtml =
    issues.length > 0
      ? `<ul class="abc-issues">${issues
          .map((i) => `<li>${i}</li>`)
          .join("")}</ul>`
      : "";
  return `<div class="section"><div${attrs}><h2${tooltipAttr}>ABC Compliance</h2><p class="narrative-line">Acceptance Baseline Criteria</p><div class="kpi-grid" style="grid-template-columns: repeat(2, 1fr);"><div class="kpi-card"><div class="label">Status</div><div class="value" style="color:${statusColor}">${
    abc.compliant ? "Compliant" : "Non-compliant"
  }</div></div><div class="kpi-card"><div class="label">Findings</div><div class="value">${
    abc.justificationOverdue + abc.remediationOverdue + abc.cveAgeExceeded
  }</div><div class="detail">overdue / exceeded</div></div></div>${issuesHtml}</div></div>`;
}

function renderSlaCompliance(
  ctx: ReportContext,
  config: Record<string, unknown>,
): string {
  const criticalDays = Number(config.criticalDays) || 15;
  const highDays = Number(config.highDays) || 35;
  const mediumDays = Number(config.mediumDays) || 180;
  const lowDays = Number(config.lowDays) || 360;
  const sla = computeSlaCompliance(
    ctx.filteredIssues,
    { criticalDays, highDays, mediumDays, lowDays },
    ctx.countMode ?? "groups",
  );
  const attrs = sectionFilterAttrs(ctx);
  if (sla.total === 0) {
    return `<div class="section"><div${attrs}><h2>SLA Compliance</h2><p class="activity-empty">No open issues to evaluate. SLA targets: Critical ${criticalDays}d, High ${highDays}d, Medium ${mediumDays}d, Low ${lowDays}d.</p></div></div>`;
  }
  const statusColor =
    sla.pctCompliant >= 80
      ? "#22c55e"
      : sla.pctCompliant >= 50
        ? "#eab308"
        : "#ef4444";
  const rows = sla.bySeverity
    .map((r) => {
      const s = r.severity.toLowerCase();
      return `<tr data-filter-severity="${filterAttr(
        s,
      )}"><td><span class="badge ${sev(s)}">${
        r.severity
      }</span></td><td class="text-right mono" style="color:#22c55e">${
        r.within
      }</td><td class="text-right mono" style="color:#ef4444">${
        r.exceeding
      }</td></tr>`;
    })
    .join("");
  return `<div class="section"><div${attrs}><h2>SLA Compliance</h2><p class="narrative-line">Findings within vs exceeding SLA (Critical ${criticalDays}d, High ${highDays}d, Medium ${mediumDays}d, Low ${lowDays}d)</p><div class="kpi-grid" style="grid-template-columns: repeat(3, 1fr);"><div class="kpi-card"><div class="label">Within SLA</div><div class="value" style="color:#22c55e">${sla.withinSla}</div><div class="detail">of ${sla.total}</div></div><div class="kpi-card"><div class="label">Exceeding SLA</div><div class="value" style="color:#ef4444">${sla.exceedingSla}</div><div class="detail">needs attention</div></div><div class="kpi-card"><div class="label">Compliant</div><div class="value" style="color:${statusColor}">${sla.pctCompliant}%</div><div class="detail">assets on track</div></div></div><table><thead><tr><th>Severity</th><th class="text-right">Within</th><th class="text-right">Exceeding</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
}

function renderCvssHeatmap(
  ctx: ReportContext,
  config: Record<string, unknown>,
): string {
  const periodDays =
    (ctx.effectivePeriodDays ?? Number(config.periodDays)) || 90;
  const w = Number(config.width) || 560;
  const h = Number(config.height) || 200;
  const countMode = ctx.countMode ?? "groups";
  const trends = computeTrendDataLastDays(
    ctx.filteredIssues,
    periodDays,
    countMode,
  );
  const attrs = sectionFilterAttrs(ctx);
  if (trends.length === 0) {
    return `<div class="section"><div${attrs}><h2>Severity Trend Heatmap</h2><p class="activity-empty">No data for the last ${periodDays} days.</p></div></div>`;
  }
  const maxTotal = Math.max(1, ...trends.map((t) => t.total));
  const pad = { left: 60, right: 20, top: 24, bottom: 32 };
  const cellW = (w - pad.left - pad.right) / trends.length;
  const cellH = (h - pad.top - pad.bottom) / 4;
  const rows = ["critical", "high", "medium", "low"];
  const heatColors = ["#ef4444", "#f97316", "#eab308", "#0ea5e9"];
  const cells: string[] = [];
  for (let ri = 0; ri < 4; ri++) {
    const sev = rows[ri] as keyof Omit<TrendDataPoint, "date" | "total">;
    for (let ci = 0; ci < trends.length; ci++) {
      const cnt = trends[ci][sev] ?? 0;
      const intensity = maxTotal > 0 ? Math.min(1, cnt / maxTotal) : 0;
      const opacity = 0.2 + intensity * 0.8;
      const x = pad.left + ci * cellW;
      const y = pad.top + ri * cellH;
      const label = cnt > 0 ? cnt : "";
      cells.push(
        `<rect x="${x}" y="${y}" width="${cellW - 2}" height="${
          cellH - 2
        }" fill="${heatColors[ri]}" opacity="${opacity}" rx="2"/><text x="${
          x + cellW / 2 - 4
        }" y="${y + cellH / 2 + 4}" text-anchor="middle" font-size="10" fill="${
          intensity > 0.5 ? "#fff" : "#334155"
        }">${label}</text>`,
      );
    }
  }
  const maxXLabels = 14;
  const nTrends = trends.length;
  const xLabelIndices =
    nTrends <= maxXLabels
      ? Array.from({ length: nTrends }, (_, i) => i)
      : Array.from({ length: maxXLabels }, (_, k) =>
          Math.round((k * (nTrends - 1)) / (maxXLabels - 1)),
        );
  const xLabels = xLabelIndices
    .map((i) => {
      const t = trends[i];
      const x = pad.left + (i + 0.5) * cellW;
      return `<text x="${x}" y="${
        h - 8
      }" text-anchor="middle" font-size="9" fill="#64748b">${t.date}</text>`;
    })
    .join("");
  const yLabels = rows
    .map((r, i) => {
      const y = pad.top + (i + 0.5) * cellH;
      return `<text x="8" y="${
        y + 4
      }" text-anchor="start" font-size="10" fill="#64748b">${r}</text>`;
    })
    .join("");
  return `<div class="section"><div${attrs}><h2>Severity Trend Heatmap</h2><p class="narrative-line">Vulnerability density by severity over time (last ${periodDays} days)</p><div class="viz-trend-wrap"><svg viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">${cells.join(
    "",
  )}${xLabels}${yLabels}</svg></div></div></div>`;
}

function renderTaskProjectsTable(ctx: ReportContext): string {
  const projects = ctx.taskProjects ?? [];
  const attrs = sectionFilterAttrs(ctx);
  if (projects.length === 0)
    return `<div class="section"><div${attrs}><h2>Task Tracking</h2><p class="activity-empty">No task tracking projects configured. Connect Jira, Linear, or another tracker in Aikido.</p></div></div>`;
  const rows = projects
    .map(
      (p) =>
        `<tr><td class="mono">${p.name}</td><td>${p.type ?? "—"}</td></tr>`,
    )
    .join("");
  return `<div class="section"><div${attrs}><h2>Task Tracking</h2><table><thead><tr><th>Project</th><th>Type</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
}

function formatTaskLinks(
  tasks: Array<{ title?: string; url?: string }> | undefined,
  noLinks?: boolean,
): string {
  if (!tasks || tasks.length === 0) return "";
  return tasks
    .map((t) => {
      const label = t.title ?? "Task";
      if (t.url && !noLinks)
        return `<a href="${t.url}" target="_blank" rel="noopener noreferrer" class="task-link">${label}</a>`;
      return `<span class="task-label">${label}</span>`;
    })
    .join(", ");
}

// ---------------------------------------------------------------------------
// Public: render one widget
// ---------------------------------------------------------------------------

export function renderWidget(
  type: WidgetType,
  context: ReportContext,
  config: Record<string, unknown>,
): string {
  switch (type) {
    case "summary":
      return renderSummary(context, config);
    case "severityDonut":
      return renderSeverityDonut(context, config);
    case "severityBar":
      return renderSeverityBar(context);
    case "sourceBar":
      return renderSourceBar(context);
    case "severityPills":
      return renderSeverityPills(context);
    case "riskGauge":
      return renderRiskGauge(context, config);
    case "trendSparkline":
      return renderTrendSparkline(context, config);
    case "trendStacked":
      return renderTrendStacked(context, config);
    case "trendTable":
      return renderTrendTable(context, config);
    case "agingBars":
      return renderAgingBars(context, config);
    case "agingTable":
      return renderAgingTable(context, config);
    case "mttrBars":
      return renderMttrBars(context);
    case "mttrTable":
      return renderMttrTable(context);
    case "repoBars":
      return renderRepoBars(context, config);
    case "repoTable":
      return renderRepoTable(context, config);
    case "topVulnsTable":
      return renderTopVulnsTable(context, config);
    case "topVulnsList":
      return renderTopVulnsList(context, config);
    case "topVulnsAdvisory":
      return renderTopVulnsAdvisory(context, config);
    case "scannerTable":
      return renderScannerTable(context, config);
    case "scannerDonut":
      return renderScannerDonut(context, config);
    case "openVsClosed":
      return renderOpenVsClosed(context);
    case "criticalHighKpi":
      return renderCriticalHighKpi(context);
    case "issueList":
      return renderIssueList(context, config);
    case "activityTimeline":
      return renderActivityTimeline(context, config);
    case "containerBars":
      return renderContainerBars(context, config);
    case "containerTable":
      return renderContainerTable(context, config);
    case "assetMixDonut":
      return renderAssetMixDonut(context, config);
    case "teamTable":
      return renderTeamTable(context, config);
    case "complianceScoreCard":
      return renderComplianceScoreCard(context, config);
    case "reachabilityMatrix":
      return renderReachabilityMatrix(context);
    case "ciScanFrequency":
      return renderCiScanFrequency(context, config);
    case "taskProjectsTable":
      return renderTaskProjectsTable(context);
    case "text":
      return renderText(context, config);
    case "slaCompliance":
      return renderSlaCompliance(context, config);
    case "abcCompliance":
      return renderABCCompliance(context, config);
    case "cvssHeatmap":
      return renderCvssHeatmap(context, config);
    default:
      return "";
  }
}
