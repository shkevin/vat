# Implementation Plan: Grouping Model

**Version:** 1.1  
**Date:** March 2026  
**Status:** Ready

---

## 1. Executive Summary

VAT currently has **derived grouping** (frontend-only, in `findingGroupUtils.ts`) but **inconsistent grouping keys** across finding types and sources. The plan defines a coherent grouping model that:

1. **Keeps grouping derived** — computed at read time, not baked in at import
2. **Separates deduplication from grouping** — distinct concerns, distinct keys
3. **Extends the canonical schema** — so parsers emit grouping-relevant fields
4. **Aligns with Aikido** — for sources that provide `issue_group_id`, we can validate; for others, we compute

---

## 2. Current State

### 2.1 Data Flow (Today)

```
[Scanner] → Parser → CanonicalFindingPayload (VatFindingSchema)
                         ↓
              ingest_finding() → fingerprint dedup → Finding (DB)
                         ↓
              VAT API → Frontend → getFindingGroupKey() → display groups
```

### 2.2 What Exists

| Layer | Location | Behavior |
|-------|----------|----------|
| **Parsers** | `backend/app/parsers/` | Trivy, Snyk, Semgrep, Gitleaks, SARIF, etc. → `VatFindingSchema` |
| **Dedup** | `backend/app/services/dedup.py` | `make_fingerprint(cve_id, component, image, branch, tag)` or `make_fingerprint_for_source_issue()` |
| **Ingest** | `backend/app/services/ingest.py` | Fingerprint lookup; merge or create |
| **Grouping** | `frontend/lib/findingGroupUtils.ts` | `getFindingGroupKey()` — CVE by `cveId`, SAST/Secret/IaC by `(findingType, normalizedTitle)` |

### 2.3 Gaps

1. **CVE vs package grouping**: Aikido groups SCA by **package name**; VAT groups by **CVE ID**. Same package with multiple CVEs → 1 group in Aikido, N groups in VAT.
2. **Missing grouping fields**: Parsers don't consistently emit `rule_id`, `cwe_id`, `ecosystem`, `secret_type` — fields needed for type-specific grouping.
3. **Dedup conflated with grouping**: Fingerprint includes `cve_id` for dedup; grouping key also uses `cve_id` for CVE. But dedup = "same finding, same location, seen again"; grouping = "related findings, one actionable item."
4. **No backend group representation**: Groups exist only in frontend; reports and metrics recompute from issues. Aikido provides `issue_group_id` but we don't persist or use it for grouping.

---

## 3. Design Principles

### 3.1 Derived Grouping (Not Import-Time)

- **Grouping is computed**, not stored. Raw Finding → normalized Finding → assigned to FindingGroup by grouping logic at read time.
- **Why**: Multi-source platform; each source may group differently. Re-grouping later must be possible without re-import.
- **Implication**: Grouping key function lives in shared logic (backend + frontend), not in DB schema.

### 3.2 Dedup vs Grouping Are Separate

| Concern | Purpose | Key | When |
|---------|---------|-----|------|
| **Deduplication** | Same finding, same location, seen again on rescan → update existing, don't create duplicate | `hash(scanner_id + rule_id + file_path + line)` or tool's `unique_id` | At ingest |
| **Grouping** | Related-but-distinct findings → surface as one actionable item | CWE/package/rule per type (see §4) | At read/display |

- **Dedup** = uniqueness constraint (DB level).
- **Grouping** = display/triage concern (computed).

### 3.3 Canonical Schema First

Before grouping, **normalize** findings from all sources into a common schema. Every parser must emit the fields required for grouping. Extend `VatFindingSchema` with optional grouping-relevant fields; parsers populate when available.

---

## 4. Grouping Keys by Finding Type

| Finding Type | Primary Group Key | Secondary (Subissues) | Notes |
|--------------|-------------------|------------------------|-------|
| **SCA** | `ecosystem` + `package_name` (component_base) | CVE IDs as subissues | One group per package; multiple CVEs in same package = one group (Aikido model). Note: use `finding_type=SCA` not CVE — CVE is an identifier, not a classifier. |
| **SAST** | `rule_id` or `cwe_id` | `file_path` for subissues | Same rule at different locations = one group |
| **IaC / Cloud** | `rule_id` (check ID) | `resource` for subissues | Same check, different resources = one group |
| **Secrets** | `secret_type` (e.g. "AWS Key") | `file_path` for subissues | Same secret type, different files = one group |
| **License** | `ecosystem` + `package_name` | — | Package-level |
| **Container** | `ecosystem` + `package_name` | `image`/`tag` for subissues | Same as SCA but scoped to container |

### 4.1 Fallbacks When Primary Key Missing

- **SCA**: No `package_name` → fall back to `cve_id` (current behavior) to avoid over-grouping.
- **SAST/IaC/Secret**: No `rule_id` → use normalized `title` (current behavior).
- **Ecosystem**: Infer from `component` (e.g. `@org/pkg` → npm) or parser metadata.

---

## 5. Schema Extensions

### 5.1 Add to VatFindingSchema (Optional Fields)

```python
# Grouping-relevant (optional; parsers populate when available)
rule_id: Optional[str] = None       # SAST, IaC, Secret rule/check ID
cwe_id: Optional[str] = None       # CWE-XXX for SAST grouping fallback
ecosystem: Optional[str] = None    # npm, pypi, go, debian, etc.
secret_type: Optional[str] = None  # "AWS Key", "Generic Secret", etc.
resource: Optional[str] = None      # IaC resource path/ARN for subissue display
```

### 5.2 Parser Mapping (Who Provides What)

| Parser | rule_id | cwe_id | ecosystem | secret_type |
|--------|---------|--------|-----------|-------------|
| Trivy (vuln) | — | — | from Target/Type | — |
| Trivy (secret) | RuleID | — | — | Category |
| Trivy (misconfig) | ID | — | — | — |
| Snyk | — | — | from packageManager | — |
| Semgrep | check_id | extra.metadata.cwe | — | — |
| Gitleaks | RuleID | — | — | Description |
| SARIF | rule.id | rule.properties.cwe | — | — |
| Grype | — | — | from namespace | — |
| npm_audit | — | — | "npm" | — |
| pip_audit | — | — | "pypi" | — |

---

## 6. Backend Grouping Logic

### 6.1 Grouping Key Function (Python)

Implement `get_finding_group_key(finding: Finding) -> str` in `backend/app/services/grouping.py`:

```python
def get_finding_group_key(f: Finding) -> str:
    """Stable group key. Same key = same logical issue (actionable item)."""
    ft = (f.finding_type or "").lower()
    # SCA: ecosystem + package (component_base). Use "sca" not "cve" — CVE is an identifier.
    if ft == "sca":
        pkg = (f.component_base or component_base(f.component or "") or "").lower()
        eco = (getattr(f, "ecosystem", None) or "").lower()
        if pkg:
            return f"sca:{eco}|{pkg}"
        return f"cve:{normalize(f.cve_id)}"  # fallback
    # SAST: rule_id or cwe_id or normalized title
    if ft == "sast":
        rid = (getattr(f, "rule_id", None) or "").strip()
        cwe = (getattr(f, "cwe_id", None) or "").strip()
        title = normalize_rule_title(f.title or f.cve_id or "")
        key = rid or cwe or title
        return f"sast:{key}"
    # IaC: rule_id or normalized title
    if ft == "iac":
        rid = (getattr(f, "rule_id", None) or "").strip()
        title = normalize_rule_title(f.title or f.cve_id or "")
        return f"iac:{rid or title}"
    # Secret: secret_type or rule_id or normalized title
    if ft == "secret":
        st = (getattr(f, "secret_type", None) or "").strip()
        rid = (getattr(f, "rule_id", None) or "").strip()
        title = normalize_rule_title(f.title or f.cve_id or "")
        return f"secret:{st or rid or title}"
    # License: ecosystem + package
    if ft == "license":
        pkg = (f.component_base or component_base(f.component or "") or "").lower()
        eco = (getattr(f, "ecosystem", None) or "").lower()
        return f"license:{eco}|{pkg}" if pkg else f"license:{f.id}"
    return f"other:{f.id}"
```

### 6.2 Frontend Alignment

Frontend `getFindingGroupKey()` must use the **same logic** (or call an API that returns the key). Options:

- **A) Shared spec**: Document the key formula; implement identically in TS and Python.
- **B) API**: `GET /api/findings/{id}/group-key` or include `group_key` in finding payload.
- **C) Backend computes groups**: API returns findings already grouped; frontend just renders.

Recommendation: **A** for v1 — keep grouping derived in both places; ensure keys match. Add `group_key` to API response later if needed.

**Technical debt**: Option A is a known debt item, not just a pragmatic choice. At ~50k findings, computing group keys client-side from a flat list becomes a UX problem. The fixture test buys time but does not eliminate the debt. **Add `GET /api/findings/groups` in Phase 2** — backend returns pre-grouped findings; frontend renders. Small incremental step, avoids future rewrite.

---

## 7. Deduplication Refinement

### 7.1 Current Fingerprint

- **With source_issue_id**: `hash(source_name:source_issue_id|image|branch|tag)` — 1:1 with source.
- **Without**: `hash(cve_id|component_base|image|branch|tag)`.

### 7.2 Dedup Key by Type (Proposed)

| Type | Dedup Key | Rationale |
|------|-----------|-----------|
| SCA | `source + (source_issue_id \|\| cve_id + component + image + branch + tag)` | Same CVE in same package, same asset = one row |
| SAST | `source + (source_issue_id \|\| rule_id + file_path + line)` | Same rule, same location = one row |
| IaC | `source + (source_issue_id \|\| rule_id + resource + image/branch)` | Same check, same resource = one row |
| Secret | `source + (source_issue_id \|\| rule_id + file_path + line)` | Same secret type, same file/line = one row |

**Implementation**: Extend `make_fingerprint` to accept `finding_type` and optional `rule_id`, `file_path`, `line`. Parsers must emit these for SAST/IaC/Secret.

---

## 8. Status and Rescan Logic

### 8.1 The Problem

When a scanner runs again and a finding **disappears** from the report:

- **Fixed**: Developer remediated → should close.
- **Not scanned**: Scanner didn't run on that file/branch → should stay open.

### 8.2 DefectDojo Approach (Reference)

- **Reimport** with `scan_date` and `close_old_findings` options.
- Findings not in the new scan are closed **only if** the test (scan) covered the same scope.
- Scope = same product, same engagement, same test type.

### 8.3 VAT Approach (Proposed)

1. **Push sources (Manual, Aikido webhook)**: No automatic close. Findings close only when:
   - Source sends `issue.closed` (Aikido) or equivalent, or
   - User marks Resolved/Suppressed in VAT.

2. **Pull sources (future)**: If VAT triggers scans and fetches results:
   - Store `last_seen_at` per finding.
   - On rescan: if finding not in new results **and** scan covered same asset (image/branch), set `last_seen_at` and optionally auto-close after N days of absence (configurable).

3. **Scope matching**: "Same asset" = same `(image, branch, tag)` or `(code_repo_id, branch)`.

**Phase**: Defer full rescan logic to a later phase. Document the decision; implement when pull-based sync exists.

---

## 9. Phased Implementation

### Phase 1: Schema + Parser Extensions (Low Risk)

| Task | Description |
|------|-------------|
| 1.1 | Add `rule_id`, `cwe_id`, `ecosystem`, `secret_type`, `resource` to `VatFindingSchema` (optional) |
| 1.2 | Add corresponding columns to `Finding` model (nullable) |
| 1.3 | Update Trivy, Snyk, Semgrep, Gitleaks parsers to populate new fields where available |
| 1.4 | Migration for new columns |
| 1.5 | Rename `finding_type` CVE → SCA in VatFindingType, FindingType; update parsers; migration (see §13.4) |

**Deliverable**: Parsers emit grouping-relevant fields; DB can store them. SCA naming is consistent.

---

### Phase 2: Backend Grouping Service (Core Logic)

| Task | Description |
|------|-------------|
| 2.1 | Create `backend/app/services/grouping.py` with `get_finding_group_key()` |
| 2.2 | Implement `normalize_rule_title()` (port from frontend) for SAST/IaC/Secret |
| 2.3 | Implement SCA grouping by `ecosystem + component_base` (not cve_id) |
| 2.4 | Unit tests for each finding type |
| 2.5 | Add `group_key` to `GET /api/vat-data` finding payload for debugging |
| 2.6 | Add `GET /api/findings/groups` — returns pre-grouped findings (reduces Option A debt; scales to 50k+ findings) |

**Deliverable**: Backend can compute group keys; API can return pre-grouped data.

---

### Phase 3: Frontend Alignment

| Task | Description |
|------|-------------|
| 3.1 | Update `getFindingGroupKey()` to use SCA grouping by `ecosystem + component_base` when available |
| 3.2 | Add `rule_id`, `cwe_id`, `ecosystem`, `secret_type` to frontend `Finding` type |
| 3.3 | Ensure `normalizeRuleTitleForGrouping` matches backend `normalize_rule_title` |
| 3.4 | Validate: kaizen-v3 (or test asset) group counts align with Aikido when source is Aikido |

**Deliverable**: Frontend grouping matches backend; counts align with Aikido for Aikido-sourced data.

---

### Phase 4: Dedup Refinement (Optional, Higher Risk)

| Task | Description |
|------|-------------|
| 4.1 | Extend `make_fingerprint` to accept `finding_type`, `rule_id`, `file_path`, `line` |
| 4.2 | SAST/IaC/Secret: use `rule_id + file_path + line` when available |
| 4.3 | **Safe fingerprint migration** (do NOT recompute in-place — causes duplicate explosion): |
|     | a) Add `fingerprint_v2` column |
|     | b) Ingest writes both old and new fingerprint |
|     | c) Lookup checks `fingerprint_v2` first, falls back to `fingerprint` |
|     | d) After full rescan cycle, drop old column |
| 4.4 | Document dedup key formula per type |

**Deliverable**: Dedup keys are type-aware; same finding rescanned does not create duplicate row.

---

### Phase 5: Rescan / Status Logic (Deferred)

| Task | Description |
|------|-------------|
| 5.1 | Document rescan behavior for push vs pull sources |
| 5.2 | Implement `last_seen_at` and auto-close for pull sources (when they exist) |
| 5.3 | Study DefectDojo `close_old_findings` and `reimport` logic |

**Deliverable**: Clear contract for when findings close; no premature closes.

---

## 10. What to Borrow

| Asset | Source | Use |
|-------|--------|-----|
| Parser patterns | DefectDojo `dojo/tools/` (MIT) | Reference when adding parsers; don't rewrite 150 |
| CWE taxonomy | MITRE CWE (free) | Grouping taxonomy for SAST |
| CVSS | NVD | Severity normalization |
| EPSS | FIRST.org | Prioritization (already used) |

---

## 11. Success Criteria

- [ ] SCA findings group by **package** (ecosystem + component_base), not by CVE
- [ ] SAST/IaC/Secret group by **rule_id** (or normalized title fallback)
- [ ] Dedup and grouping use distinct keys; behavior is documented
- [ ] Parsers emit `rule_id`, `ecosystem`, etc. where available
- [ ] Frontend and backend grouping logic produce identical keys
- [ ] Aikido-sourced findings: VAT group counts match Aikido (when `source_issue_group_id` can be used for validation)
- [ ] **Group severity rollup**: Max severity — group severity = highest severity among its findings (documented; frontend and backend use same formula)
- [ ] **Phase 4**: SAST/IaC/Secret dedup keys use `rule_id + file_path + line` when available; same finding rescanned does not create a duplicate row

---

## 12. Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Breaking existing reports | Phase 2–3: additive; fallback to current keys when new fields missing |
| Parser churn | Phase 1: new fields optional; parsers updated incrementally |
| Aikido mismatch | Keep `source_issue_group_id`; use for validation, not as primary key (multi-source) |
| Over-grouping SCA | Fallback: if no component_base, use cve_id (current behavior) |

---

## 13. Edge Cases and Future Work

### 13.1 Package Name Normalization (Implemented)

`normalize_package_name(ecosystem, name)` in `grouping.py`:
- **npm**: case-insensitive (Lodash == lodash)
- **PyPI**: PEP 503 — `re.sub(r"[-_.]+", "-", name).lower()` (My.Weird_Package → my-weird-package)
- **Maven/Gradle**: full groupId:artifactId required, lowercased. **Raises ValueError** if `:` missing — loud failure at parse/group time, easier to debug than silent collisions.

### 13.2 CWE Extraction (Implemented)

`app/parsers/utils.py::extract_cwe_id()` — shared by Semgrep, Trivy, SARIF, CodeQL. Handles:
- List: `["CWE-89: SQL Injection", "CWE-943: ..."]`
- String: `"CWE-89: SQL Injection"` or `"CWE-89"`
- Integer: `89` → `"CWE-89"`

### 13.3 Frontend/Backend Drift Protection

- **Fixture**: `backend/tests/fixtures/grouping_keys.json` — canonical expected keys. Backend test `test_group_key_fixture_parity` asserts `get_finding_group_key` matches.
- **Frontend**: `frontend/lib/findingGroupUtils.test.ts` loads `frontend/tests/fixtures/grouping_keys.json` (sync with backend) and asserts `getFindingGroupKey()` produces identical keys.
- **CI guard**: `test_fixture_covers_all_finding_types` fails if a finding_type has no fixture entry — prevents stale fixture when new parser/type is added.
- **Ingest validation**: `VatFindingSchema` (Pydantic) validates `finding_type` against `VatFindingType` enum. Unknown values are rejected at parse time. New parsers must use the enum; typos or unmapped scanner types fail before storage.
- **Future**: Consider storing `group_key` on Finding at ingest; frontend reads it instead of recomputing. Enables fast `GROUP BY group_key` queries.

### 13.4 Finding Type and CVE — Rename to SCA

**Naming inconsistency**: §6.1 branches on `ft == "cve"` but CVE is an identifier, not a classifier (§13.4). This causes confusion — why does the SCA branch check for "cve"? **Rename `finding_type` CVE → SCA** in the enum and throughout (VatFindingType, FindingType, parsers, grouping logic, fixtures). Small change now, confusing forever if left. Requires enum migration and parser updates.

### 13.5 Cross-Scanner Dedup

Same finding from two scanners (e.g. Snyk + Dependabot both report lodash@4.17.20 with CVE-2021-23337) produces two Findings with the same group key — **correct**. They coexist as subissues under one group. Do not deduplicate across scanners (avoids merge complexity). Surface source clearly in the UI so users don't think it's two separate problems.

**Group-level severity rollup**: Deduplicate before aggregating. **Formula: Max severity** — group severity = highest severity among its findings. If Snyk and Dependabot both report the same CVE as Critical, the group severity is Critical once. Same for counts in the UI. (Alternative: weighted score / Aikido-style severity_score integer — defer to v2.)

### 13.6 GET /api/findings/groups Response Shape

```
GET /api/findings/groups?asset=...&status=...&limit=...&offset=...
```

**Response**:
```json
{
  "groups": [
    {
      "groupKey": "sca:npm|lodash",
      "severity": "Critical",
      "findingCount": 3,
      "findings": [ /* full Finding objects, or IDs only — pick one in Phase 2 */ ]
    }
  ],
  "total": 42
}
```

- **Pagination**: `limit`/`offset` or cursor; `total` for UI.
- **Findings**: Decide deliberately in Phase 2 — not by default. **Embedded full objects**: simpler for frontend, but pagination semantics get awkward (are you paginating groups or findings?). **IDs-only + `GET /api/findings?groupKey=...`**: more composable; frontend fetches details on demand. Neither is wrong.
- **Severity**: Max severity of group (see §13.5).

### 13.7 Rule Title Normalization (Implemented)

`normalize_rule_title(title)` — strip location suffixes so same rule at different locations groups together. Frontend/backend must match exactly.

1. Strip `", path and N others"` or `", path, path and N others"` (regex: `, [^,]+(, [^,]+)? and \d+ others?$`)
2. Strip ` in <path>` when path has known extension (`.py`, `.ts`, `.tsx`, `.js`, `.jsx`, `.json`, `.yml`, `.yaml`, `.md`, `.txt`, `.xml`, `.html`, `.css`, `.sh`, `.go`, `.rs`, `.java`, `.kt`, `.env`, `.tf`, `.hcl`, `.toml`, `.lock` — IaC/secret types included)
3. Strip ` in <path>` when path is extensionless: `Dockerfile`, `Makefile`, `.dockerignore`, `.gitignore`
4. Strip ` at line N in <path>` or ` at line N-N in <path>`
5. Final: `strip().lower()`

### 13.9 Grouping Refinements (Implemented)

- **Ecosystem normalization**: npm/yarn/pnpm share the same registry; all normalize to `"npm"` for grouping so same package from different package managers groups together.
- **Component base fallback**: When `component_base` is missing, extract from `component` when it looks like `"name version"` (e.g. `lodash 4.17.21` → `lodash`). Parsers should emit `component_base`; this is a best-effort fallback.
- **Frontend/backend parity**: Frontend uses `findingType` only for SCA — no `cveId` fallback. Both sides must match exactly.

### 13.11 Aikido Adapter SCA Grouping (Implemented)

- **component_base**: Aikido adapter uses `dedup.component_base()` which strips version from both `name@version` and `"name version"` formats (e.g. `vllm 0.8.5.post1+cpu` → `vllm`). Previously only `@` was handled, causing `sca:|vllm 0.8.5.post1+cpu` keys.
- **ecosystem inference**: When Aikido does not provide `ecosystem` or `package_manager`, the adapter infers it for SCA/License findings from: (1) `programming_language` if present, (2) package name patterns (e.g. `.` in name → pypi, `org.`/`com.` → maven), (3) repo name (e.g. `images`/`container` in name → debian).
- **dedup.component_base**: Extended to strip `"name version"` format so fingerprints and grouping keys align.

### 13.12 Grouping Scoped Within Asset (Implemented)

- **Asset context**: Group keys include `#{image}|{branch}|{tag}` so grouping is **within asset only**. Same package (e.g. `urllib3`) in different repos, branches, or container tags = **separate groups**.
- **Key format**: `{type_key}#{asset}` — e.g. `sca:pypi|urllib3#kamiwaza-extensions-ontology|main|` vs `sca:pypi|urllib3#kamiwaza|develop|`.
- **Backend**: `_asset_key(f)` in `grouping.py`; frontend: `assetKey(f)` in `findingGroupUtils.ts`.

### 13.13 Status Management (Deferred)

**Key decision upfront**: Does a FindingGroup have its own independent status, or is it always derived from the aggregate status of its Findings? Aikido treats it as derived; DefectDojo lets you set it independently. **Derived is simpler and less surprising to users.**

When all Findings in a group get resolved:
- Does the group close? Does it reopen if a new matching finding comes in later?
- State machine: group status = resolved when all sub-issues resolved; reopens when new finding matches.
- Study DefectDojo `close_old_findings` and reimport logic before implementing.

---

## 14. File Summary

| Path | Action |
|------|--------|
| `backend/app/schemas/vat.py` | Add optional grouping fields |
| `backend/app/models/finding.py` | Add nullable columns |
| `backend/app/services/grouping.py` | Create — `get_finding_group_key`, `normalize_rule_title`, `normalize_package_name` |
| `backend/app/parsers/utils.py` | Create — `extract_cwe_id` (shared by Semgrep, Trivy, SARIF, CodeQL) |
| `backend/app/parsers/*.py` | Update — populate rule_id, ecosystem, etc. |
| `frontend/lib/findingGroupUtils.ts` | Update — SCA by package; use rule_id when available |
| `frontend/tests/fixtures/grouping_keys.json` | Copy of backend fixture for frontend parity test; keep in sync |
| `frontend/lib/findingGroupUtils.test.ts` | Add — fixture parity test; CI guard for all finding types |
| `frontend/types/index.ts` | Add grouping fields to Finding type |
| `backend/alembic/versions/` | Migration for new columns |
