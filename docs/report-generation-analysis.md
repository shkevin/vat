# Report Generation Analysis — Why Reports Aren't Correct

This document traces the full data flow from source to rendered report and identifies root causes for incorrect severity counts, total counts, trend data, and filter behavior.

---

## 1. Data Flow Overview

```
API (findings) 
  → useVATData (toFinding maps sourceGroupSeverity)
  → VAT.tsx passes findings to ReportTab
  → ReportTab: toVATDashboardData(findings, allAssets, { groupFindings })
  → ReportBuilderView: computeReportContext(data, definition.filters)
  → buildReportHtmlFromDefinition(context, definition, { preview: true })
  → HTML with embedded client script (filter bar + report body)
```

---

## 2. Root Cause: Wrong Findings Passed to Report

**Location:** `VAT.tsx` line 218

**Bug:** The report receives `findings` (all API findings) instead of `reportFilteredFindings` (findings that belong to displayed assets, respecting sidebar filters).

```tsx
// Current (wrong):
<ReportTab findings={findings} allAssets={reportAssets} ... />

// Should be:
<ReportTab findings={reportFilteredFindings} allAssets={reportAssets} ... />
```

**Impact:** When sidebar filters are applied (status, ABC, asset type, favorites, search), the Findings tab shows filtered data but the Report shows all findings. Counts and severity distribution will not match what the user sees in the Findings tab.

**Design intent (from ReportTab):** "Report uses Findings as the single source of truth so that data shown in Findings and Report are identical. Sidebar filters are applied upstream; report respects those filters."

---

## 2b. Root Cause B: Assets/Repos Built from Wrong Findings

**Location:** `ReportTab.tsx` — `toVATDashboardData(findings, allAssets, ...)`

**Bug:** `allAssets` comes from `reportAssets` (derived from **all** findings). `assetsToVATReportRepos(assets)` uses `asset.findings` to compute per-asset counts. So repo/container counts are based on **all** findings, while `issues` and `issueGroups` are built from whatever `findings` we pass. When we fix Root Cause A and pass `reportFilteredFindings`, we must also pass assets derived from those same findings.

**Fix:** In `ReportTab`, derive assets from the findings passed, instead of using `allAssets` from the parent:

```tsx
const assetsForReport = useMemo(() => deriveAssets(findings, SEV_ORDER), [findings]);
const data = useMemo(
  () => toVATDashboardData(findings, assetsForReport, "VAT", { groupFindings }),
  [findings, assetsForReport, groupFindings]
);
return <ReportBuilderView data={data} allAssets={assetsForReport} ... />;
```

This ensures issues, issueGroups, and repos/containers all use the same filtered dataset.

---

## 3. Preview Truncation (500 Issues)

**Location:** `report-engine.ts` — `PREVIEW_MAX_ISSUES = 500`, `buildReportDataPayload` with `maxIssues` when `preview: true`

**Behavior:** The client-side filter script receives only the first 500 issues. When there are more than 500 issues:

- **Server-rendered HTML:** Correct (built from full `context.filteredIssues`)
- **Client script:** Recomputes counts/trends from truncated payload → overwrites correct values with wrong ones

**Fixes already applied:**
- `serverCounts`, `totalOpen`, `serverTrendMetrics` added to payload when truncated
- `useServerCounts` used when `truncated && noFilters` to avoid overwriting
- Trend stacked chart not overwritten when `useServerCounts`
- Severity distribution, summary KPI, trend top bar use server values when truncated + no filters

**Remaining gap:** When filters ARE applied with truncated data, the client still recomputes from the truncated list. Filtered counts will be wrong (e.g. "Critical only" shows counts from first 500 issues, not full dataset).

---

## 4. Group ID Mismatch Risk (issue_group_id vs group_id)

**Location:** `vatReportAdapter.ts` — `findingsToVATReportIssues` vs `findingsToVATReportIssueGroups`

**Logic:**
- `findingsToVATReportIssues`: assigns `issue_group_id` from `groupMap.get(key)` where key = `getFindingGroupKey(f)`
- `findingsToVATReportIssueGroups`: assigns `group_id: i + 1` from index in `byKey.entries()`

Both use the same `groupFindingsByKey` map. Iteration order of `keys()` and `entries()` matches, so `group_id` and `issue_group_id` should align.

**Potential issue:** If the backend or Aikido uses `sourceIssueGroupId` for grouping, VAT's `getFindingGroupKey` produces different groups. The adapter does not use `sourceIssueGroupId`; it always uses its own grouping. Severity from `sourceGroupSeverity` is used per-finding and per-group, but group boundaries are VAT's, not the source's.

---

## 5. Severity Source (sourceGroupSeverity)

**Location:** `vatReportAdapter.ts`, `useVATData.ts` (toFinding)

**Flow:**
- API returns `sourceGroupSeverity` when available (e.g. Aikido)
- `toFinding` maps it: `sourceGroupSeverity: raw.sourceGroupSeverity ? String(raw.sourceGroupSeverity) : undefined`
- `findingsToVATReportIssues`: `issueSeverity = f.sourceGroupSeverity?.trim() || f.severity ?? "info"`
- `findingsToVATReportIssueGroups`: prefers `sourceGroupSeverity` when any finding in group has it

**Status:** Correctly wired. If the API does not return `sourceGroupSeverity`, fallback to `f.severity` is used.

---

## 6. resolveOpenCounts Logic

**Location:** `metrics.ts` — `resolveOpenCounts`

**Order of precedence:**
1. `issueCounts` (API) when `!hasFilters && countMode === "groups"` — **never used** because `toVATDashboardData` does not set `issueCounts`
2. `issueGroups` when `countMode === "groups"` — uses group-level severity from `issueGroups` for groups present in `openIssues`
3. `computeSeverityCountsByGroups(openIssues)` — derives severity from issue-level data when no issueGroups
4. `computeSeverityCounts(openIssues)` — instance mode

**Status:** When `issueGroups` is provided (always from `toVATDashboardData`), path 2 is used. Group severity comes from `issueGroups`, which uses `sourceGroupSeverity` when available.

---

## 7. Client-Side Filter Script

**Location:** `report-engine.ts` — inline script in `buildReportFilterBar`

**Responsibilities:**
- Show/hide DOM elements by `data-filter-severity`, `data-filter-repo`, etc.
- Update aggregate widgets (summary, severity distribution, trend) from `reportData.issues`

**Issues:**
1. **Truncation:** When `reportData.issues` is truncated to 500, filtered views use wrong data.
2. **Visibility cache:** Cleared each run to avoid stale state.
3. **Filter config vs DOM:** `cfg` from `getReportFilterConfig(context)` uses full context. DOM elements have `data-filter-*` from server render. When truncated, server-rendered rows are limited by `PREVIEW_LIMITS` (e.g. issue list 50 rows). Filtering operates on that subset.

---

## 8. PREVIEW_LIMITS vs PREVIEW_MAX_ISSUES

**Two different limits:**
- `PREVIEW_LIMITS`: Per-widget (e.g. issueList limit 50, repoTable 15) — caps rows/sections in server-rendered HTML
- `PREVIEW_MAX_ISSUES`: 500 — caps the payload for the client filter script

**Effect:** The report body may show 50 issue rows (from PREVIEW_LIMITS), but the filter script has 500 issues. Severity/repo filter logic runs on 500 issues; visibility runs on the DOM (50 rows). Counts from the script can still be wrong when total issues > 500.

---

## 9. Summary of Fixes Needed

| Issue | Fix |
|-------|-----|
| **Wrong findings passed** | In `VAT.tsx`, pass `reportFilteredFindings` instead of `findings` to `ReportTab` |
| **Assets/repos from wrong data** | In `ReportTab`, derive assets from findings (not `allAssets`) so repo/container counts match the filtered findings |
| **Truncation with filters** | When truncated and filters applied, either: (a) disable client updates for aggregates, or (b) increase `PREVIEW_MAX_ISSUES`, or (c) add a notice that filtered counts are approximate |
| **issueCounts unused** | If API provides counts, add `issueCounts` to `toVATDashboardData` for unfiltered accuracy |
| **Filter dropdown behavior** | Verify `reportFilteredFindings` fix; ensure visibility logic uses same filter semantics as Findings tab |

---

## 10. Recommended Fixes (in order)

**1. VAT.tsx:** Pass `reportFilteredFindings` instead of `findings`:

```tsx
<ReportTab findings={reportFilteredFindings} allAssets={reportAssets} ... />
```

**2. ReportTab.tsx:** Derive assets from findings so issues, groups, and repos use the same dataset:

```tsx
import { deriveAssets } from "@/lib/assetUtils";
import { SEV_ORDER } from "@/lib/constants";

const assetsForReport = useMemo(() => deriveAssets(findings, SEV_ORDER), [findings]);
const data = useMemo(
  () => toVATDashboardData(findings, assetsForReport, "VAT", { groupFindings }),
  [findings, assetsForReport, groupFindings]
);
return <ReportBuilderView data={data} allAssets={assetsForReport} groupFindings={groupFindings} />;
```

This aligns the report with the Findings tab and ensures repo/container counts match the filtered findings.
