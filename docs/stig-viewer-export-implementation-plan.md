# STIG Viewer Export Implementation Plan

## Summary

Enable VAT export to include OpenSCAP STIG findings in formats importable by STIG Viewer (XCCDF results and/or CKL). IronBank's pipeline stores raw OpenSCAP output and exports it for STIG Viewer; we need equivalent storage and export.

---

## 1. STIG Viewer Import Formats

| Format | Description | STIG Viewer Support |
|--------|--------------|---------------------|
| **XCCDF** | NIST checklist XML with `<Benchmark>` and `<TestResult>`. OpenSCAP outputs this directly. | Yes – import XCCDF results |
| **CKL** | DISA Checklist XML – `<CHECKLIST>`, `<VULN>`, `<STIG_DATA>`, `<STATUS>`. Used for manual review, waivers, comments. | Yes – primary format |

**Recommendation**: Store raw XCCDF results XML at ingest time. Export can include both:
- Raw XCCDF files (one per asset/scan) – direct STIG Viewer import
- Optionally: CKL with VAT status overlays (waivers, justifications)

---

## 2. Current Data Flow & Gaps

### What We Ingest (OpenSCAP parser)

- **Input**: XCCDF 1.1/1.2 Benchmark XML with `<TestResult>` and `<rule-result>` (fail)
- **Extracted**: `cve_id`, `rule_id`, `title`, `description`, `severity`, `component`, `file_path`, `snippet_masked`, `references`
- **Stored in Finding**: `cve_id`, `rule_id`, `title`, `description`, `severity`, `component`, `image`, `file_path`, `snippet_masked`, `source`

### What We Lose

| Field | In Parser | In Finding Model | In Export |
|-------|-----------|------------------|-----------|
| `references` | Yes (refs[:20]) | **No** – not in model | Lost |
| Raw XCCDF XML | Available at ingest | **No** – discarded | Lost |
| Benchmark ID | Not extracted | No | Lost |
| Full rule metadata (fix, check-content-ref) | Not extracted | No | Lost |

### Why This Matters for STIG Viewer

- **XCCDF export**: Needs the original `<Benchmark>` + `<TestResult>` structure. Without storing raw XML, we cannot produce valid XCCDF.
- **CKL export**: Needs `Rule_ID`, `Group_Title`, `Vuln_Num`, severity, status. We have `rule_id`, `title`, `severity`, `status` – enough for a minimal CKL, but `references` and benchmark metadata improve fidelity.

---

## 3. Storage Design

### Option A: Store Raw XCCDF per Scan (Recommended)

Add a table to persist raw OpenSCAP output:

```sql
-- New table: openscap_scan_results
CREATE TABLE openscap_scan_results (
    id VARCHAR(32) PRIMARY KEY,
    source_id VARCHAR(64) NOT NULL,
    asset_id VARCHAR(256) NOT NULL,      -- target from TestResult
    raw_xccdf_xml BYTEA NOT NULL,
    benchmark_id VARCHAR(256),
    created_at TIMESTAMP DEFAULT NOW(),
    tenant_id VARCHAR(64)
);

CREATE INDEX ix_openscap_scan_asset ON openscap_scan_results(asset_id);
CREATE INDEX ix_openscap_scan_source ON openscap_scan_results(source_id);
CREATE INDEX ix_openscap_scan_tenant ON openscap_scan_results(tenant_id);
```

**Flow**:
1. On ingest (parser `openscap` or `openscap_oval`): after parsing, store `raw` (bytes) in `openscap_scan_results` keyed by `asset_id` + `source_id`.
2. Deduplication: overwrite or version by `(asset_id, source_id)` so latest scan wins.
3. Export: read `openscap_scan_results` for tenant, add each `raw_xccdf_xml` as `{asset_id}.xccdf.xml` in the ZIP.

**Pros**: Full fidelity, no schema changes to Finding, STIG Viewer can import directly.  
**Cons**: Duplicate storage (findings + raw XML). For OpenSCAP-only scans, raw XML is the source of truth.

### Option B: Store OpenSCAP Metadata in Finding

Add columns to `findings`:

```sql
ALTER TABLE findings ADD COLUMN references JSONB;  -- list of ref URLs
ALTER TABLE findings ADD COLUMN benchmark_id VARCHAR(256);
ALTER TABLE findings ADD COLUMN raw_rule_xml TEXT;  -- optional: single rule snippet
```

**Pros**: No new table.  
**Cons**: Cannot reconstruct full XCCDF; CKL generation would be from our normalized data, which may not match STIG Viewer expectations for rule IDs and STIG_DATA.

### Option C: Hybrid (Recommended for IronBank Parity)

- **Store raw XCCDF** in `openscap_scan_results` (Option A).
- **Optionally** add `references` to Finding for display and CKL enrichment.

---

## 4. Export Implementation

### 4.1 Add OpenSCAP Results to Export Bundle

In `build_export_bundle`:

1. Query `openscap_scan_results` for `tenant_id`.
2. For each row:
   - Decode `raw_xccdf_xml` to string.
   - Add to ZIP: `stig/{asset_id}.xccdf.xml` (sanitize `asset_id` for filename).
3. Include a manifest: `stig/manifest.json` listing `{ asset_id, filename, created_at }`.

### 4.2 Status Overlay (Optional Enhancement)

VAT tracks status (Open, Resolved, False Positive, Not Applicable, etc.). STIG Viewer uses:

- `Not_Reviewed`, `Open`, `NotAFinding`, `Not_Applicable`, etc.

We could:
- Parse stored XCCDF, update `<rule-result>` status based on VAT finding status, re-serialize.
- Or generate CKL with VAT status mapped to CKL `<STATUS>` and `<FINDING_DETAILS>`.

This requires matching VAT findings to XCCDF rule-results by `rule_id` + `asset_id`.

### 4.3 CKL Generation (Optional)

If we need CKL (e.g., for tools that only accept CKL):

- Use stored XCCDF to get full rule metadata.
- Build CKL XML per DISA schema (CHECKLIST > STIGS > iSTIG > VULN > STIG_DATA, STATUS, FINDING_DETAILS).
- Map VAT status → CKL status.
- Include justification/reviewer_note in FINDING_DETAILS.

---

## 5. Implementation Tasks

### Phase 1: Storage

1. **Migration**: Create `openscap_scan_results` table.
2. **Ingest**: In `_ingest_from_parser`, when `parser_id in ("openscap", "openscap_oval")` and `raw` is bytes:
   - Extract `asset_id` from `_extract_asset_from_report` or from first payload's `image`.
   - Upsert `openscap_scan_results` (asset_id, source_id, raw_xccdf_xml, tenant_id).
3. **Deduplication**: Use `(asset_id, source_id)` as unique key; overwrite on re-scan.

### Phase 2: Export

1. **Export service**: In `build_export_bundle`, add:
   - Query `openscap_scan_results` for tenant.
   - For each result, add `stig/{safe_asset_id}.xccdf.xml` to ZIP.
   - Add `stig/manifest.json`.
2. **API**: No change – export bundle already returns ZIP.

### Phase 3 (Optional): Status Overlay & CKL

1. Parse XCCDF, match rule-results to VAT findings by `rule_id` + `image`.
2. Update `<result>` or add override attributes based on VAT status.
3. Or implement CKL generator for full STIG Viewer workflow.

---

## 6. IronBank Alignment

IronBank's pipeline:
- Runs OpenSCAP (oscap-docker) on container images.
- Stores/archives scan output.
- Exports in formats consumable by STIG Viewer.

Our approach mirrors this by:
- Storing raw XCCDF at ingest (equivalent to archiving scan output).
- Including it in export for STIG Viewer import.
- Keeping the option to add CKL and status overlays for waiver/review workflow.

---

## 8. Implementation Status

**Implemented (2026-03-09)**:
- `openscap_scan_results` table (migration 021)
- `OpenSCAPScanResult` model
- `store_openscap_scan_result` on ingest (openscap, openscap_oval)
- `build_export_bundle` includes `stig/{asset}_{source}.xccdf.xml` (or `.oval-results.xml`) and `manifest.json`

**Usage**:
- Ingest OpenSCAP XML via POST /api/ingest (parser=openscap or openscap_oval)
- Download export bundle via GET /api/export/bundle
- Extract `vat-export-{date}/stig/` folder and import XCCDF files into STIG Viewer

---

## 9. References

- [STIG Viewer 3.x User Guide](https://dl.dod.cyber.mil/wp-content/uploads/stigs/pdf/U_STIG_Viewer_3-x_User_Guide_V1R4.pdf)
- [genckl](https://github.com/ap1x/genckl) – CKL generation from XCCDF
- [mitre/ckl2ckl](https://github.com/mitre/ckl2ckl) – CKL format handling
- [IronBank stigviewer](https://repo1.dso.mil/ironbank-tools/stigviewer) (archived)
- [OpenSCAP XCCDF 1.2](http://checklists.nist.gov/xccdf/1.2)
