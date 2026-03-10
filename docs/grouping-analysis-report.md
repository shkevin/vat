# VAT Finding Group Aggregation — Analysis Report

**Date:** March 3, 2026  
**Reference:** `data/exports/aikido_sync_2026-03-03_121856.xlsx` (ungrouped raw dataset)  
**Scope:** Per-asset grouping logic validation across all 70+ assets

---

## 1. Executive Summary

The VAT finding group aggregation logic has been thoroughly analyzed. **No logical issues were detected.** Grouping is correctly scoped within each asset (image|branch|tag), and findings from different assets do not group together. The implementation aligns with the design in `docs/implementation-plan-grouping-model.md` §13.12.

### Independent Playwright Validation (March 3, 2026)

Validation was performed via **Playwright MCP** against the live VAT backend API (`GET /api/findings/groups`):

- **831 groups** fetched and validated
- **0 cross-asset leaks** — every finding in each group has `image|branch|tag` matching the group key suffix
- **0 suffix mismatches** — every group key contains `#` and the suffix matches all embedded findings
- **Per-asset sampling** — `kamiwaza`, `kamiwaza/images/vllm`, `containers/images/opensearch` each returned groups with `allSameAsset: true`

| Metric | Value |
|--------|-------|
| Total findings (VAT DB) | 2,648 |
| Total VAT groups | 831 |
| Total assets | 127 (unique image\|branch\|tag combinations) |
| Excel Aikido groups | 519 |
| Cross-asset leaks | 0 |

---

## 2. Grouping Logic Overview

### 2.1 Asset Key

Grouping is scoped by **asset context** = `image|branch|tag`:

- **Containers:** `image` = full path (e.g. `kamiwaza/images/vllm`), `tag` = image tag (e.g. `latest`)
- **Code repos:** `image` = repo name (e.g. `kamiwaza`), `branch` = git branch (e.g. `develop`)

Same logical issue (e.g. CVE in `urllib3`) in different assets → **separate groups**.

### 2.2 Group Keys by Finding Type

| Type | Primary Key | Example |
|------|-------------|---------|
| **SCA** | `ecosystem` + `component_base` (package) | `sca:debian|vllm#kamiwaza/images/vllm\|\|latest` |
| **SAST** | `rule_id` or `cwe_id` or normalized title | `sast:potential file inclusion attack...#kamiwaza\|develop\|` |
| **IaC** | `rule_id` or normalized title | `iac:avd-123#...` |
| **Secret** | `secret_type` or `rule_id` or title (path preserved) | `secret:leaked secret in install.sh#...` |
| **License** | `ecosystem` + `component_base` | `license:npm|pkg#...` |

### 2.3 Key Format

All keys end with `#{image}|{branch}|{tag}` so grouping is **within-asset only**.

---

## 3. Per-Asset Analysis Results

### 3.1 Sample Assets — Grouping Behavior

**Container: kamiwaza/images/vllm (tag=latest)**
- 51 findings → 24 groups
- SCA: `vllm` package has 19 CVEs in one group ✓
- SCA: `vim-data`, `vim-minimal`, `glibc`, `filelock` each group multiple CVEs ✓

**Container: kamiwaza/images/whisper-cpp (tag=latest)**
- 157 findings → 56 groups
- SCA: `ffmpeg` has 43 CVEs in one group ✓
- SCA: `curl`, `libmfx1`, `cairo`, `libtiff` each group multiple CVEs ✓

**Code repo: kamiwaza (branch=develop)**
- 384 findings → 141 groups
- SAST: "Potential file inclusion attack" → 94 findings in one group ✓
- SAST: "3rd party Github Actions should be pinned" → 20 findings ✓
- Secret: "leaked secret in containers/manifests/03-secret.yaml" → 11 findings (per-file grouping) ✓

### 3.2 Validation Checks Performed

1. **Asset suffix in key:** Every group key ends with `#{asset}` and suffix matches the asset.
2. **Cross-asset leak:** No finding in a group has a different asset than the group’s asset.
3. **Type-specific grouping:**
   - SCA: Same package + ecosystem → one group per asset ✓
   - SAST: Same rule_id/title → one group per asset ✓
   - Secret: Title includes path → each file = separate group ✓

---

## 4. Excel vs VAT Comparison

### 4.1 Asset Key Mismatch (Excel Export)

The Excel export does not include `tag` for containers. As a result:

- **Excel:** `kamiwaza/images/vllm` → asset key `kamiwaza/images/vllm||`
- **VAT DB:** Same findings stored with `tag=latest` → asset key `kamiwaza/images/vllm||latest`

So Excel and VAT use different asset keys for containers. The analysis script normalizes container paths (no branch parsing for `/images/` paths) but does not infer tag from Excel.

### 4.2 Group Count Difference

| Source | Groups |
|--------|--------|
| Excel (Aikido issue_group_id) | 519 |
| VAT (computed get_finding_group_key) | 831 |

**Expected.** VAT and Aikido use different grouping logic:

- **VAT SCA:** Groups by `ecosystem + package` — one group per package per asset.
- **VAT Secret:** Groups by title (path preserved) — one group per file.
- **Aikido:** May group differently (e.g. broader Secret grouping).

---

## 5. Edge Cases Verified

### 5.1 Container Names with Hyphens

Names like `whisper-cpp` and `extension-operator` are not parsed as `repo (branch)`. The analysis script treats paths containing `/images/` as container paths and does not apply branch parsing.

### 5.2 Same Package, Different Assets

- `urllib3` in `repo-a|main|` vs `repo-b|main|` → different groups ✓ (covered by `test_grouping_scoped_within_asset`)

### 5.3 Secret Per-File Grouping

Secrets in different files (e.g. `install.sh` vs `postlaunch.sh`) form separate groups, as intended.

---

## 6. Recommendations

1. **Excel export:** Consider adding a `tag` column for container findings so Excel asset keys align with VAT.
2. **Group count parity:** VAT’s 831 vs Aikido’s 519 is expected; document differences for users.
3. **Empty ecosystem:** Some SCA groups have `sca:|pkg` (empty ecosystem). Parsers should populate `ecosystem` where possible.

---

## 7. Files Referenced

| File | Purpose |
|------|---------|
| `backend/app/services/grouping.py` | Core grouping logic |
| `backend/app/api/findings.py` | `GET /api/findings/groups` endpoint |
| `backend/scripts/grouping_analysis_per_asset.py` | Analysis script |
| `backend/tests/test_grouping.py` | Unit tests |
| `docs/implementation-plan-grouping-model.md` | Design spec |

---

## 8. How to Re-run Analysis

```bash
cd backend
uv run python scripts/grouping_analysis_per_asset.py [path/to/excel.xlsx]
```

If no path is given, uses the latest `.xlsx` in `data/exports/`.
