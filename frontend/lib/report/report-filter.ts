/**
 * Report filter bar - shared by report-engine and report-widgets.
 */
import type { ReportContext } from "./report-types";

/** Asset type values used in report (Code, Container, VM, Package, Other). */
export const REPORT_ASSET_TYPES = ["Code", "Container", "VM", "Package", "Other"] as const;

export interface ReportFilterConfig {
  severities: string[];
  assetTypes: string[];
  assets: string[];
  branches: string[];
}

export function getReportFilterConfig(context: ReportContext): ReportFilterConfig {
  const severityOrder = ["critical", "high", "medium", "low", "info"] as const;
  const severitiesWithCount = severityOrder.filter((s) => (context.counts[s] ?? 0) > 0);
  // Always include critical, high, medium, low when we have any issues, so users can filter by
  // severity even if counts are incomplete or pre-filtered. Prevents "only showing low" when
  // higher severities exist but were excluded from the filter bar.
  const standardSeverities = ["critical", "high", "medium", "low"] as const;
  const hasIssues = (context.openIssues ?? 0) > 0 || (context.filteredIssues?.length ?? 0) > 0;
  const severities = hasIssues
    ? [...new Set([...standardSeverities, ...severitiesWithCount])]
    : severitiesWithCount;
  const assetTypes: string[] = [];
  const mix = context.assetMix;
  if ((mix?.code ?? 0) > 0) assetTypes.push("Code");
  if ((mix?.container ?? 0) > 0) assetTypes.push("Container");
  if ((mix?.vm ?? 0) > 0) assetTypes.push("VM");
  if ((mix?.package ?? 0) > 0) assetTypes.push("Package");
  if ((mix?.other ?? 0) > 0) assetTypes.push("Other");
  if (assetTypes.length === 0 && hasIssues) assetTypes.push(...REPORT_ASSET_TYPES);
  const assets = new Set<string>();
  for (const r of context.repoRisk) {
    if (r.repo) assets.add(r.repo);
  }
  for (const c of context.containerRisk) {
    if (c.repo) assets.add(c.repo);
  }
  for (const i of context.filteredIssues) {
    if (i.repository) assets.add(i.repository);
  }
  const branches = new Set<string>();
  for (const i of context.filteredIssues) {
    if (i.branch) branches.add(i.branch);
  }
  return {
    severities,
    assetTypes,
    assets: Array.from(assets).sort(),
    branches: Array.from(branches).sort(),
  };
}

export function buildReportFilterBarStructure(
  filterConfig: ReportFilterConfig,
  borderColor: string,
  mutedColor: string,
  inline = false
): string {
  const esc = (s: string) =>
    s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/"/g, "&quot;");
  const sevOptions = filterConfig.severities
    .map(
      (s) =>
        `<label class="report-filter-option" data-filter="severity" data-value="${esc(s)}"><input type="checkbox" value="${esc(s)}" data-filter="severity" checked> <span class="report-filter-option-label">${esc(s.charAt(0).toUpperCase() + s.slice(1))}</span><span class="report-filter-count" data-count-for="${esc(s)}"></span></label>`
    )
    .join("");
  const assetOptions = filterConfig.assets
    .map(
      (a) =>
        `<label class="report-filter-option" data-filter="asset" data-value="${esc(a)}"><input type="checkbox" value="${esc(a)}" data-filter="asset"> <span class="report-filter-option-label" title="${esc(a)}">${esc(a.length > 40 ? a.slice(0, 37) + "…" : a)}</span><span class="report-filter-count" data-count-for="${esc(a)}"></span></label>`
    )
    .join("");
  const assetTypeOptions = filterConfig.assetTypes
    .map(
      (t) =>
        `<label class="report-filter-option" data-filter="assetType" data-value="${esc(t)}"><input type="checkbox" value="${esc(t)}" data-filter="assetType" checked> <span class="report-filter-option-label">${esc(t)}</span><span class="report-filter-count" data-count-for="${esc(t)}"></span></label>`
    )
    .join("");
  const branchOptions = filterConfig.branches
    .map(
      (b) =>
        `<label class="report-filter-option" data-filter="branch" data-value="${esc(b)}"><input type="checkbox" value="${esc(b)}" data-filter="branch"> <span class="report-filter-option-label">${esc(b)}</span><span class="report-filter-count" data-count-for="${esc(b)}"></span></label>`
    )
    .join("");
  const hasAssetTypes = filterConfig.assetTypes.length > 0;
  const hasAssets = filterConfig.assets.length > 0;
  const hasBranches = filterConfig.branches.length > 0;
  const hasSearchAssets = filterConfig.assets.length > 5;
  const hasSearchBranches = filterConfig.branches.length > 5;
  const idAttr = inline ? "" : ' id="report-filter-bar"';
  const chipsId = inline ? "" : ' id="report-filter-chips"';
  return `<div${idAttr} class="report-filter-bar${inline ? " report-filter-bar-inline" : ""}" style="border-color:${borderColor};color:${mutedColor}">
  <div class="report-filter-facets">
    <div class="report-filter-dd" data-dd="severity">
      <button type="button" class="report-filter-trigger" aria-haspopup="listbox">Severity <span class="report-filter-arrow">▾</span></button>
      <div class="report-filter-panel" data-panel="severity">
        <div class="report-filter-panel-inner">
          ${sevOptions}
          <div class="report-filter-actions"><button type="button" data-select-all="severity">Select all</button><button type="button" data-clear="severity">Clear</button></div>
        </div>
      </div>
    </div>
    ${hasAssetTypes ? `<div class="report-filter-dd" data-dd="assetType">
      <button type="button" class="report-filter-trigger" aria-haspopup="listbox">Asset type <span class="report-filter-arrow">▾</span></button>
      <div class="report-filter-panel" data-panel="assetType">
        <div class="report-filter-panel-inner">
          ${assetTypeOptions}
          <div class="report-filter-actions"><button type="button" data-select-all="assetType">Select all</button><button type="button" data-clear="assetType">Clear</button></div>
        </div>
      </div>
    </div>` : ""}
    ${hasAssets ? `<div class="report-filter-dd" data-dd="asset">
      <button type="button" class="report-filter-trigger" aria-haspopup="listbox">Asset <span class="report-filter-arrow">▾</span></button>
      <div class="report-filter-panel" data-panel="asset">
        ${hasSearchAssets ? `<input type="search" class="report-filter-search" placeholder="Search assets…" data-search="asset" autocomplete="off">` : ""}
        <div class="report-filter-panel-inner">
          ${assetOptions}
          <div class="report-filter-actions"><button type="button" data-select-all="asset">Select all</button><button type="button" data-clear="asset">Clear</button></div>
        </div>
      </div>
    </div>` : ""}
    ${hasBranches ? `<div class="report-filter-dd" data-dd="branch">
      <button type="button" class="report-filter-trigger" aria-haspopup="listbox">Branch <span class="report-filter-arrow">▾</span></button>
      <div class="report-filter-panel" data-panel="branch">
        ${hasSearchBranches ? `<input type="search" class="report-filter-search" placeholder="Search branches…" data-search="branch" autocomplete="off">` : ""}
        <div class="report-filter-panel-inner">
          ${branchOptions}
          <div class="report-filter-actions"><button type="button" data-select-all="branch">Select all</button><button type="button" data-clear="branch">Clear</button></div>
        </div>
      </div>
    </div>` : ""}
  </div>
  <div class="report-filter-chips"${chipsId}></div>
  <button type="button" class="report-filter-clear" ${inline ? "" : 'id="report-filter-clear-all" '}>Clear all filters</button>
</div>`;
}
