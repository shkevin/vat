# Report Builder Severity/Filtering Analysis

**Date:** 2026-03-04  
**Excel baseline:** `data/exports/aikido_sync_2026-03-04_192444.xlsx`

---

## 1. Executive Summary

The report builder can show incorrect severity counts and filtering behavior due to several identified issues:

1. **Repo/container severity uses per-finding severity instead of group severity** — `assetsToVATReportRepos` uses `f.severity` while the main report uses `sourceGroupSeverity`. When Aikido assigns group-level severity (e.g. "high" for reachability) that differs from individual finding severity, repo counts will be wrong.

2. **Data source mismatch** — The Excel export is from Aikido sync (SettingsKV). The report uses VAT API (`/vat-data`) which reads from the Finding model. These can differ if Aikido full sync hasn't populated the DB or if webhook vs sync have different data.

3. **Excel IssueCounts sheet is all zeros** — The latest export has `total: 0, open: 0, critical: 0, ...` in IssueCounts. This suggests the Aikido sync either didn't receive issue counts from the API or the export structure has a gap.

4. **Truncation with filters** — When there are >500 issues and the user applies severity/repo filters, the client-side filter script recomputes from a truncated payload, producing wrong counts.

---

## 2. Excel Baseline (Raw Data)

From `aikido_sync_2026-03-04_192444.xlsx`:

| Metric | Value |
|--------|-------|
| Total issues (Issues sheet) | 2,811 |
| **Severity (all)** | low: 1,456, medium: 798, high: 488, critical: 69 |
| **Severity (open only)** | medium: 660, high: 326, low: 257, critical: 48 |
| **Total open** | 1,291 |
| IssueCounts sheet | **All zeros** (total: 0, open: 0, critical: 0, …) |

Columns in Issues sheet: `affected_package`, `affected_version`, `closed_at`, `cve_id`, `description`, `first_detected_at`, `fixed_version`, `issue_group_id`, `issue_id`, `last_detected_at`, `repository`, `scanner_type`, `severity`, `severity_score`, `status`, `title`, `vat_status`.

---

## 3. Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Excel Export (Aikido Sync)                                                  │
│ • Source: aikido_dashboard_sync → SettingsKV → export_aikido_sync_to_excel  │
│ • Same data as Aikido dashboard cache                                       │
│ • Does NOT write to Finding model                                           │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ Report (VAT Frontend)                                                        │
│ • Source: /api/vat-data → list_findings (Finding model)                      │
│ • Enriched with sourceGroupSeverity from Aikido cache (SettingsKV)           │
│ • reportFilteredFindings = findings filtered by displayedAssets (sidebar)    │
│ • ReportTab → toVATDashboardData(findings, assetsForReport)                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key point:** Excel and report can show different data if:
- Aikido full sync has not run (Finding model empty or stale)
- Aikido webhook populates Finding model with different data than sync
- Sidebar filters (favorites, asset type, status, etc.) reduce reportFilteredFindings

---

## 4. Root Causes

### 4.1 Repo/Container Severity Uses Per-Finding Severity (Bug)

**Location:** `frontend/lib/report/vatReportAdapter.ts` — `assetsToVATReportRepos` → `severityKey(f)`

**Current code:**
```typescript
function severityKey(f: Finding): "critical" | "high" | "medium" | "low" {
  const s = (f.severity ?? "").toLowerCase();  // ← Uses per-finding severity
  // ...
}
```

**Issue:** The main report uses `sourceGroupSeverity` (Aikido group-level severity) for issues and groups. Repo/container counts use `f.severity` (per-finding). When Aikido assigns group severity (e.g. "high" for reachability) that differs from individual finding severity, repo risk tables and severity distribution will be inconsistent.

**Fix:** Use `sourceGroupSeverity` when available, same as `findingsToVATReportIssues`:
```typescript
function severityKey(f: Finding): "critical" | "high" | "medium" | "low" {
  const s = (f.sourceGroupSeverity?.trim() || f.severity ?? "").toLowerCase();
  // ...
}
```

---

### 4.2 deriveAssets / computeMetricsFromFindings Uses f.severity

**Location:** `frontend/lib/assetUtils.ts` — `computeMetricsFromFindings`, `severityToKey`

**Issue:** Asset-level ORA and verified % use `f.severity`. For consistency with the report, these should prefer `sourceGroupSeverity` when available.

---

### 4.3 Truncation With Filters

**Location:** `frontend/lib/report/report-engine.ts` — `buildReportDataPayload`, `PREVIEW_MAX_ISSUES = 500`

**Issue:** When there are >500 issues:
- Server-rendered HTML uses full `context.filteredIssues` (correct)
- Client filter script receives only first 500 issues
- When user applies severity/repo filter, script recomputes from truncated list → wrong counts

**Mitigation:** `serverCounts` and `totalOpen` are passed when truncated, and `useServerCounts` is used when `truncated && noFilters`. But when filters ARE applied with truncated data, counts are wrong.

**Options:**
- Increase `PREVIEW_MAX_ISSUES` (e.g. 2000)
- Disable client aggregate updates when truncated + filters applied
- Show notice: "Filtered counts are approximate when viewing large datasets"

---

### 4.4 Excel IssueCounts All Zeros

**Location:** `backend/app/services/aikido_export.py` — `export_aikido_sync_to_excel`

**Issue:** The IssueCounts sheet shows all zeros. The sync stores `issue_counts` from `fetch_aikido_issue_counts`. Either:
- The Aikido API returned empty/zero counts
- The sync data structure uses a different key (e.g. `issueCounts` vs `issue_counts`)
- The export flattens counts incorrectly

**Impact:** Validation scripts that compare Excel IssueCounts to VAT cannot use this sheet. The Issues sheet severity distribution is the authoritative baseline for comparison.

---

### 4.5 sourceGroupSeverity Enrichment Requires sourceIssueGroupId

**Location:** `backend/app/services/findings_service.py` — `enrich_findings_with_source_group_severity`

**Logic:** Enrichment matches `sourceIssueGroupId` from each finding to Aikido group `id`/`group_id`. If a finding lacks `sourceIssueGroupId`, it does not get `sourceGroupSeverity` and falls back to `f.severity`.

**Issue:** Findings from non-Aikido sources or older ingestions may not have `sourceIssueGroupId`. In that case, the report uses per-finding severity.

---

## 5. Severity Filter Logic (Correct)

The severity filter in `computeReportContext` and the client script is correct:

```typescript
// report-engine.ts
if (filters.severityFilter.length > 0) {
  const allowed = new Set(filters.severityFilter.map((s) => s.toLowerCase()));
  issues = issues.filter((i) => allowed.has((i.severity ?? "").toLowerCase()));
}
```

The issue severity comes from `sourceGroupSeverity || severity` in `findingsToVATReportIssues`, so filtering by severity is consistent with the main report.

---

## 6. Recommended Fixes (Priority Order)

| # | Fix | Location | Effort |
|---|-----|----------|--------|
| 1 | Use sourceGroupSeverity in assetsToVATReportRepos | vatReportAdapter.ts | Low |
| 2 | Use sourceGroupSeverity in deriveAssets / computeMetricsFromFindings | assetUtils.ts | Low |
| 3 | Increase PREVIEW_MAX_ISSUES or add truncation notice | report-engine.ts | Low |
| 4 | Debug Excel IssueCounts export | aikido_export.py, aikido_dashboard_sync | Medium |
| 5 | Ensure Aikido full sync populates Finding model for report parity | aikido_full_sync.py | Medium |

---

## 7. Verification Steps

1. **Compare Excel vs report (same data):** Run Aikido full sync to populate Finding model, then compare:
   - Excel Issues sheet severity (open) vs report severity distribution
   - Excel total open vs report total open

2. **Test severity filter:** Select "Critical" only → verify counts match filtered issues

3. **Test with >500 issues:** Apply severity filter → verify counts are not from truncated subset

4. **Test repo risk table:** Verify repo critical/high/medium/low counts match group severity when sourceGroupSeverity differs from per-finding severity
