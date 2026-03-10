# Report Builder vs Findings Page Totals Mismatch — Root Cause Analysis

## Summary

The Report Builder totals do not match the Findings page because of **two main discrepancies**:

1. **Status filter**: Findings page counts **all** findings (including Resolved, Suppressed, etc.); Report counts **open** only.
2. **Data source**: Report receives **all** findings; Findings page uses **sidebar-filtered** assets.

---

## 1. Status Filter (Primary Cause)

### Findings Page (`AssetsTable.tsx`)

```179:207:frontend/components/assets/AssetsTable.tsx
  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const sev of SEV_ORDER) counts[sev] = 0;
    if (effectiveGroupFindings) {
      const seenGroups = new Set<string>();
      for (const asset of displayedAssets) {
        for (const f of asset.findings) {
          // ... counts EVERY finding, no status filter
          counts[key] = (counts[key] ?? 0) + 1;
        }
      }
    } else {
      for (const asset of displayedAssets) {
        for (const f of asset.findings) {
          // ... counts EVERY finding, no status filter
          counts[key] = (counts[key] ?? 0) + 1;
        }
      }
    }
```

**Behavior**: Counts **all** findings in `asset.findings` — Open, Resolved, False Positive, Suppressed, Approved, etc.

### Report (`report-engine.ts`, `metrics.ts`)

```427:434:frontend/lib/report/report-engine.ts
  const openIssues = issues.filter(isOpen)
  // ...
  const { totalOpen, counts } = resolveOpenCounts(openIssues, ...)
```

```132:148:frontend/lib/report/metrics.ts
/** Statuses treated as closed (not open). */
const EXCLUDED_OPEN_STATUSES = [
  "closed", "resolved", "ignored", "auto_ignored",
  "false positive", "suppressed", "approved", "duplicate",
  "not applicable", "rejected",
];

export function isOpen(issue: VATReportIssue): boolean {
  const st = (issue.status ?? "").toLowerCase();
  return !EXCLUDED_OPEN_STATUSES.includes(st);
}
```

**Behavior**: Counts **open** findings only. Excludes Resolved, False Positive, Suppressed, Approved, etc.

### Impact

- Findings page: Critical 64 + High 691 + Medium 936 + Low 1656 = **3,347** (all statuses)
- Report: OPEN 1605, Critical+High 523 (open only)

The Report will always show **fewer** counts when many findings are resolved/suppressed.

---

## 2. Data Source Difference

### Report Tab (`VAT.tsx`)

```284:296:frontend/components/VAT.tsx
    if (view === "report") {
      return (
        <ReportTab
          findings={findings}
          allAssets={reportAssets}
          ...
        />
      );
    }
```

- `findings` = **all** findings from the API (no sidebar filtering)
- `reportAssets` = all assets (`assetsFromApi` or derived from all findings)

### Findings Page

- Uses `displayedAssets`, which are filtered by:
  - `filterFindingStatuses` (Needs Justification, Justified, Verified, etc.)
  - `filterABC` (Compliant, Non-compliant)
  - `filterVerifiedRange`, `filterORARange`
  - `filterAssetTypes` (Code, Container, VM, Package, Other)
  - `onlyFavorites`
  - `search`

### ReportTab Comment

```21:24:frontend/components/report/ReportTab.tsx
/**
 * Report uses the same filtered data as the Findings tab (displayedAssets).
 * Sidebar filters (status, asset type, ABC, verified, ORA, favorites, search)
 * are applied upstream in useVATData; report receives those filtered assets
 * and findings so report and Findings are identical.
 */
```

**This comment is incorrect.** The Report receives `findings` and `reportAssets`, not `reportFilteredFindings` and `displayedAssets`. The Report does **not** apply sidebar filters; it uses the full dataset and only applies report definition filters (repo, severity, asset type, date).

### Impact

- With sidebar filters (e.g. Only Favorites, specific asset types), the Findings page shows a subset.
- The Report uses the full dataset and applies its own filters. So the report can include findings from assets that the sidebar filtered out.

---

## 3. Backend Consistency

The backend (`vat_data.py`, `findings_service.py`, `assets_service.py`) returns all findings and assets without filtering by status. The backend does not distinguish "open" vs "closed" for the `/vat-data` response — it returns everything. Status filtering is done client-side.

---

## Recommended Fixes (Applied)

### Fix 1: Align Findings Page Severity Counts with Report (Open Only) ✓

In `AssetsTable.tsx`, filter findings to open status when computing severity counts:

```ts
const CLOSED = ["Resolved", "False Positive", "Duplicate", "Not Applicable", "Approved", "Suppressed"];
// In severityCounts, when iterating:
for (const f of asset.findings) {
  if (CLOSED.includes(f.status ?? "")) continue;  // skip closed
  // ... count
}
```

This makes the Findings page severity pills match the Report's "open" semantics.

### Fix 2: Report Uses Sidebar-Filtered Data ✓

In `VAT.tsx`, pass `reportFilteredFindings` and `displayedAssets` (or equivalent) to the Report instead of `findings` and `reportAssets`:

```tsx
<ReportTab
  findings={reportFilteredFindings}
  allAssets={displayedAssets}
  ...
/>
```

This ensures the Report and Findings page operate on the same data subset when sidebar filters are applied.

### Fix 3: Update ReportTab Comment ✓

Correct the comment in `ReportTab.tsx` to reflect that it currently receives `findings` and `reportAssets`, not the filtered data. After Fix 2, the comment would be accurate.

---

## Files to Modify

| File | Change |
|------|--------|
| `frontend/components/assets/AssetsTable.tsx` | Filter to open-only when counting severity |
| `frontend/components/VAT.tsx` | Pass `reportFilteredFindings` and `displayedAssets` to ReportTab |
| `frontend/components/report/ReportTab.tsx` | Update comment (and props if needed) |
