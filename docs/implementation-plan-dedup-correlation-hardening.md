# Implementation Plan: Dedup, Correlation & Scanner Extensibility

**Version:** 1.3  
**Date:** March 2026  
**Status:** Draft  
**Related:** `implementation-plan-grouping-model.md`, `PRD-audit-asset-mapping-dedup.md`, container tag canonicalization plan (auto-alias / digest conflicts)

---

## 1. Executive Summary

VAT already separates **replay deduplication** (`fingerprint_id`) from **cross-source correlation** (`correlation_key`, edges, scoring). Gaps versus industry practice: **digest-aware asset identity**, **deeper package/CVE normalization**, **SARIF-grade static fingerprints**, and **scanner-specific identity hooks** scattered across `ingest.py` instead of a single extension surface.

This plan hardens identity and correlation while making **new scanners cheap to add**: one **canonical payload** contract, one **identity strategy registry**, parsers stay thin adapters, and behavior is **test-driven** per scanner profile.

---

## 2. Goals & Non-Goals

### 2.1 Goals

1. **Class-specific identity** — Keep typed correlation keys; refine inputs (normalization, scope) without breaking API consumers.
2. **Pluggable scanner identity** — Add a scanner/parser without editing `ingest_finding()` branches for each tool.
3. **Strong normalization** — Centralize component and CVE string normalization; optional later: external catalog hints (OSV) without blocking ingest.
4. **Deployment scope** — Canonical container image key + observed tag/digest (align with container canonicalization work); optional digest in correlation when policy says so.
5. **Static analysis parity** — Prefer SARIF `partialFingerprints` where present; fallback to rule + path + line/snippet hash.
6. **Explicit uncertainty** — Preserve correlation confidence tiers, scoring, audit events; avoid silent merges.
7. **Parity** — Backend grouping/correlation helpers remain the source of truth; frontend mirrors via shared contracts or generated snippets (existing direction).

### 2.2 Non-Goals (This Phase)

- Replacing all of Aikido/sync with a new bus.
- ML-based duplicate detection.
- Mandatory network calls to NVD/OSV on every ingest (optional enrichment may be a later phase).

---

## 3. Current Architecture (Anchor)

```
Scanner output → Parser (IngestParser) → VatFindingSchema
       → ingest_fingerprint_strategy (today: inline in ingest.py)
       → correlation_key_for_payload()
       → DB Finding
       → apply_correlation_linking() / edges / audit
```

**Registry today:** `backend/app/parsers/__init__.py` — `ParserDescriptor` already carries `strong_fields`, asset extractors. **Extend** this rather than inventing a parallel registry.

---

## 4. Design Principles

### 4.1 Strategy Pattern for “How We Identify a Finding Instance”

Introduce a small **identity strategy** interface (names illustrative):

| Responsibility | Method | Notes |
|----------------|--------|--------|
| **Dedup fingerprint** | `compute_fingerprint(payload, source_name) -> str` | Replaces scattered `if openscap / elif source_issue_id / else make_fingerprint` in ingest |
| **Correlation inputs** | Optional enrich/normalize before `correlation_key_for_payload` | e.g. strip tag from image ref once canonicalization exists |
| **Identifier facts** | Optional `extract_identifier_facts(payload) -> list[(namespace, value)]` | Feeds existing `finding_identifiers` / crosswalks |

**Default strategy** implements current behavior (CVE+component+image+branch+tag+source_name, source_issue override, OpenSCAP as separate module calling `make_openscap_fingerprint`).

**Per-parser override** only where needed: register `parser_id → strategy` in one module (e.g. `app/services/ingest_identity.py` or `app/parsers/identity_strategies.py`).

**Why:** `ingest_finding()` stays orchestration-only; new scanner = new parser class + optional strategy class + descriptor row — **no new `if` in ingest**.

### 4.2 Single Canonical Contract (`VatFindingSchema`)

All scanners map into **one** schema. New fields are **optional** and versioned in the schema docstring / OpenAPI:

- **Already useful:** `rule_id`, `file_path`, `line`, `ecosystem`, `component_base`, `stable_rule_key`, `benchmark_*`, `image_digest`, `source_issue_id`.
- **Add (planned):** `partial_fingerprints: dict[str, str] | None` (SARIF), `purl: str | None` or `package_url: str | None` when parsers can emit it, `scanner_identity: str | None` (opaque stable id from tool when not SARIF).

Parsers must not compute business keys ad hoc in random dicts — only schema fields.

### 4.3 Normalization Pipeline (Pure Functions)

Introduce `app/services/identity_normalization.py` (or split by concern, e.g. `identity_normalization/cve.py`, `package.py` if the file grows):

- **`normalize_cve_id(s) -> str`** — CVE-YYYY-NNNN… form.
- **`normalize_package(ecosystem, name, version?) -> PackageKey` dataclass** — Reuse and **call from** `grouping.normalize_package_name` / `dedup.component_base` to avoid drift (consider moving grouping helpers here and re-exporting).
- **Idempotent, no I/O** — Easy unit tests; optional “enrichment” layer later calls OSV with same `PackageKey`.

**Module boundary (non-negotiable):** `identity_normalization` exposes **pure transformation functions only** — no database access, no network I/O, no reads of Django/settings except where passed in as arguments. Anything with side effects (calling OSV, loading tenant config) lives in a separate **enrichment** or **ingest** layer that *calls* these pure functions. This prevents the module becoming an unmaintainable grab-bag and keeps unit tests fast.

Correlation and fingerprint code **import** these helpers; parsers do not each implement their own trim logic.

### 4.4 Correlation Key Versioning — **Decision**

**Use a string prefix on `correlation_key` itself** (e.g. `v1:sca:…`, `v2:sca:…` when semantics change).

| Approach | Rationale |
|----------|-----------|
| **Key prefix (chosen)** | Visible in DB rows and logs without joins; no migration to add a column; version churn is obvious when debugging. |
| **Separate `correlation_key_schema_version` column** | Defer unless SQL filtering/indexing by version is required at scale. Can be added later without changing the prefix convention. |

**Implement prefix in Phase B** alongside normalization so every newly written key uses the same generation rules. Backfill or dual-read only if historical keys lack a prefix (document migration note).

### 4.5 SARIF `partialFingerprints` — Precedence and Hashing

SARIF allows multiple `partialFingerprints` keys (e.g. `primaryLocationLineHash/v1`, `contextRegionHash/v1`); producers name them differently. **Do not** hash the raw dict in arbitrary key order without a policy.

**Precedence for “primary dedup material” (document in `sarif.py` and tests):**

1. Prefer `primaryLocationLineHash/v1` if present (GitHub-flavored SARIF commonly emits this family).
2. Else `primaryLocationLineHash` (any suffix).
3. Else `contextRegionHash/v1` or `contextRegionHash` if present.
4. Else **deterministic fallback**: sort keys lexicographically, concatenate `key=value` pairs, hash (SHA-256 hex) — record which branch was used in parser debug logs.

When adding support for another well-known key (e.g. a vendor-specific stable id), insert it in this list with a documented position **above** the sorted-all-keys fallback.

**Conflict:** If multiple keys from the same precedence tier exist, use the first match in the ordered list above; if still ambiguous, use sorted-all-keys hash of **only** the `partialFingerprints` object.

### 4.6 Fingerprint Input Hierarchy (`DefaultFingerprintStrategy`)

Document in the **strategy class docstring** (single source of truth for precedence):

1. **`source_issue_id`** — When present, use existing `make_fingerprint_for_source_issue` (unchanged unless Phase A explicitly adjusts).
2. **OpenSCAP** — Delegated strategy / `make_openscap_fingerprint` (unchanged).
3. **`partial_fingerprints`** — If present (resolved per §4.5), use **resolved partial fingerprint hash** as stable static identity (preferred over line/snippet for SARIF producers that emit fingerprints).
4. **`scanner_identity`** — If set (opaque stable id from the tool for non-SARIF, or when SARIF lacks usable `partialFingerprints`), use as the primary stable input to the fingerprint material **before** any computed rule/path/line hash.
5. **Computed fallback** — Rule id + normalized file path + **line** + snippet (see Phase C: when §4.5 material exists, **line is excluded** from this fallback).

Parsers must **set** `scanner_identity` only when the tool provides a vendor-stable id; do not invent collisions across tools in parser code — that belongs in normalization.

### 4.7 Testing Pattern for New Scanners

For each new parser:

1. **Fixture** — Minimal real or anonymized scan output in `backend/tests/fixtures/`.
2. **Parser test** — Assert canonical fields + snapshot of `fingerprint` + `correlation_key` (golden strings) given frozen normalization.
3. **Integration** — One ingest creates finding; second ingest same payload merges; different payload same correlation cluster behaves as expected.

Add a **checklist** in `backend/app/parsers/README.md` (short): register descriptor, optional identity strategy, tests, strong_fields.

---

## 5. Phased Implementation

### Phase A — Identity strategy extraction (foundation)

**Work**

1. Define `FingerprintStrategy` (protocol) + `DefaultFingerprintStrategy` + `OpenSCAPFingerprintStrategy` (delegate to existing `make_openscap_fingerprint`).
2. Move fingerprint selection from `ingest.py` into a resolver: `resolve_fingerprint_strategy(source_name, parser_id)`.
3. Keep **byte-for-byte** same fingerprints for existing fixtures in phase A (regression tests must pass).

**Exit criteria:** No behavior change; `ingest.py` shorter; 100% existing tests green.

**Audit / tenant:** Verify `tenant_id` is unchanged in correlation cluster queries (`select_correlation_cluster` in `correlation_linking.py` already scopes by tenant — add regression test if missing).

---

### Phase B — Normalization centralization

**Sequence:** Complete **`docs/correlation-field-matrix.md` first** (full table, replace placeholder), **then** implement normalization and wiring. Writing the matrix before code forces explicit field decisions; tests and implementation are checked against the matrix rather than documenting after the fact.

**Work**

1. **Deliverable first — field matrix:** Finish `docs/correlation-field-matrix.md`: one table with **columns** = Fingerprint | Correlation key | Grouping key | Notes; **rows** = finding-type / scanner class (incl. OpenSCAP). Link from this plan. Review against §4.4 (`v1:` prefix) and current `correlation.py` / `dedup.py` / `grouping.py`.
2. Add `identity_normalization` module (§4.3 boundaries); wire `correlation_key_for_payload` and `make_fingerprint` to use `normalize_cve_id` and shared package extraction.
3. Apply **correlation key prefix** `v1:` per §4.4 for all newly generated keys.
4. Add unit tests for edge cases (npm scopes, PyPI PEP 503, empty ecosystem); assert behavior matches the matrix.

**Exit criteria:** Field matrix merged and reviewed **before** normalization PR merges; grouping keys unchanged for frontend parity tests; new correlation keys use `v1:` prefix; migration note if any historical key format changes.

---

### Phase C — SARIF & static finding hardening

**Work**

1. Extend `SarifParser` to read `result.partialFingerprints` (and `fingerprints` if present); map into `partial_fingerprints` on schema; apply **§4.5 precedence** in code and unit tests.
2. Extend fingerprint strategy per §4.6: when **resolved partial fingerprint material exists**, **do not** include `line` in the computed fingerprint fallback (line may still be stored on `Finding` for display).
3. When **no** `partialFingerprints` (or empty after resolution), **include** `line` (and normalized path + rule) in computed fingerprint material — **no** line-number tolerance window in v1 (same line only); document tolerance as a future enhancement if needed.
4. Correlation: include stable partial fingerprint segment in key for SAST when available (e.g. `v1:sast:…:fp:<hash>` suffix).

**Exit criteria:**

- Golden tests: two SARIF results differ only in `startLine` but share the same resolved partial fingerprint → **same fingerprint** (dedup merges).
- Golden tests: SARIF without partialFingerprints, same rule + path, **different** line → **different fingerprint**.
- Parser documents which `partialFingerprints` key won per §4.5 in debug output or structured ingest metadata (for audits).

---

### Phase D — Asset & digest scope (ties to container plan)

**Work**

1. After canonical `canonical_asset_key` exists (see container tag canonicalization plan), pass **canonical** image id into fingerprint/correlation **asset** segment; keep `observed_tag` / `image_digest` on `Finding` for evidence.
2. Optional product flag: `VAT_CORRELATION_INCLUDE_DIGEST=1` to append digest to correlation key for container SCA when strict deployment binding is required.
3. Wire digest conflict signals into asset API (already sketched in your plan).

**Exit criteria (testable):**

- **API:** Asset detail response (or dedicated sub-resource) exposes **digest conflict** state for a canonical asset when the same tag has been observed with **≥2 distinct digests** — include a field suitable for a **badge** in the UI (e.g. `digestConflict: true` plus minimal detail). **Latency:** conflict state visible on the **next successful read** after ingest completes (same request/session as ingest is acceptable for v1; document if async).
- **Integration test:** Two ingests with same canonical repo/image/tag but **different** `image_digest` emit the conflict signal; **optional** second test with `VAT_CORRELATION_INCLUDE_DIGEST=1` asserts **different** `correlation_key` than with flag off for the same logical image pair (or document equivalent assertion on fingerprint material).
- **Docs:** `VAT_CORRELATION_INCLUDE_DIGEST` and canonical asset behavior described in `docs/correlation-linking-architecture.md` or container plan (not only env.example).

---

### Phase E — Parser registry & developer ergonomics

**Work**

1. Expand `ParserDescriptor` with `identity_strategy_id: str | None` and `default_finding_type_hint` if needed.
2. **Stub generator (optional):** Add `scripts/new_scanner_stub.py` or cookiecutter template **only if** scanner integrations are frequent enough to justify maintenance; otherwise **Phase B deliverable** + `backend/app/parsers/README.md` checklist is sufficient. **One-time heuristic:** inspect history — e.g. `git log --diff-filter=A --oneline -- backend/app/parsers/*.py` (or new parser commits under `parsers/`). If **fewer than four** new parser files in the **last 12 months**, skip the stub generator unless product asks otherwise. (Roughly equivalent to “≥1 new scanner per quarter” over a year, but data-driven.)
3. Optional: OpenAPI snippet for `VatFindingSchema` in CI to catch breaking field removals.

**Exit criteria:** New scanner integration steps fit on one page (README checklist minimum); code review checklist is obvious.

---

## 6. Risk Register

| Risk | Mitigation |
|------|------------|
| Fingerprint change remaps DB rows | Phase A must preserve hashes; later phases use key versioning + backfill scripts |
| Over-merging SCA across ecosystems | Normalization tests; `ecosystem` required for high-confidence SCA correlation |
| Correlation key explosion | Truncate hashed segments to fixed length; index on prefix |
| Frontend/backend group key drift | Single Python module as source; generate TS or test parity (`findingGroupUtils.test.ts` pattern) |
| **Large correlation clusters** (`correlation_key` too coarse) | Today `apply_correlation_linking` loads **all** findings sharing a key (scoped by `tenant_id`) and scores each non-canonical member against the canonical — **O(k)** per ingest for cluster size **k**, not O(n²) over the whole DB; **k** can still be huge if keys are coarse (e.g. missing asset/ecosystem). Mitigation: keep keys sufficiently specific (asset segment, ecosystem, component); monitor cluster size in metrics; optional cap or split policy if k exceeds a threshold; **cross-asset correlation only with an explicit product policy flag** if ever added. |
| Multi-tenant data leakage | All correlation and audit paths must filter by `tenant_id` where applicable — regression tests in Phase A; see §11.1. |

---

## 7. File Touchpoints (Expected)

| Area | Files |
|------|--------|
| Identity strategies | New: `app/services/ingest_identity.py` or `app/parsers/identity_strategies.py` |
| Ingest | `app/services/ingest.py` (slim down) |
| Correlation | `app/services/correlation.py`, `app/services/correlation_scoring.py` |
| Normalization | New: `app/services/identity_normalization.py`; possibly merge with `grouping.py` imports |
| Schema | `app/schemas/vat.py` |
| SARIF | `app/parsers/sarif.py` |
| Registry | `app/parsers/__init__.py` |
| Tests | `backend/tests/test_*identity*`, parser fixtures, integration ingest |
| Docs | This file; `docs/correlation-field-matrix.md` (Phase B); update `correlation-linking-architecture.md` |

---

## 8. Success Metrics

1. **New scanner** — Parser + descriptor + tests added without modifying `ingest_finding` control flow (only registry wiring).
2. **No regression** — Existing integration tests for correlation, grouping parity, OpenSCAP, ingest pass.
3. **Explainability** — Any auto-link has audit + edge evidence; correlation key computable from documented fields.
4. **Optional digest policy** — Operators can choose stricter deployment binding without code forks.

---

## 9. Suggested Order of Execution

1. Phase A (refactor, no behavior change)  
2. Phase B (normalization)  
3. Phase C (SARIF) — high value for static tools  
4. Phase D — coordinate with container canonicalization migration  
5. Phase E — polish and templates  

Phases B and C can partially overlap once A is stable.

---

## 10. Alignment With Strong VMS / Enterprise Practice

This plan matches patterns used across **standards bodies**, **open-source VMS platforms**, and **documented commercial products**. The table below names **where each pattern is established** so we do not treat VAT-specific choices as universal—follow the cited sources when in doubt.

| Industry pattern | In this plan | Primary sources (standards & systems) |
|------------------|--------------|--------------------------------------|
| **Layered identity** (scan row vs vulnerability vs asset/context) | Yes — fingerprint vs correlation vs grouping | **DefectDojo**: deduplication scoped by product/engagement, separate from “finding” lifecycle (`docs/content/triage_findings/finding_deduplication/about_deduplication.md` in DefectDojo). **OWASP Dependency-Track**: component + vulnerability as first-class objects (dependency graph model). **GitHub Advanced Security**: SARIF results as instances vs security advisories. |
| **Per-parser hash + optional tool unique id** | Partial — VAT uses fingerprint + `source_issue_id`; plan adds strategy registry | **DefectDojo**: `HASHCODE_FIELDS_PER_SCANNER`, `HASH_CODE_FIELDS_ALWAYS`, algorithms `hash_code` / `unique_id_from_tool` / `unique_id_from_tool_or_hash_code` (`dojo/settings/settings.dist.py`, deduplication docs). Same model as configurable field lists in several enterprise suites. |
| **Class-specific keys** (SCA vs static vs compliance) | Yes — `correlation_key_for_payload`, OpenSCAP `stable_rule_key` | **Commercial** (public docs): asset/CVE/plugin-style IDs (e.g. **Tenable** plugin ID + asset, **Qualys** QID + host) separate “what” from “where.” **NIST**: CVE as weakness identifier; **DISA STIG / XCCDF** (OpenSCAP): rule and benchmark identity for compliance findings—not interchangeable with CVE-only keys. |
| **Normalization layer** (package/CVE strings) | Phase B; optional OSV later | **OSV** (Open Source Vulnerabilities, OSSF / Google): package identity + vuln id schema. **CycloneDX** / **SPDX**: vuln references tied to components. **NVD/CVE** (MITRE/NIST): canonical CVE IDs. |
| **Deployment / asset scope** (image, tag, digest) | Phase D + container plan | **OCI** image manifest & digest model (content-addressed artifacts). **DefectDojo**: `service` in hash by default (`HASH_CODE_FIELDS_ALWAYS`). Commercial tools universally scope by **asset/inventory record** + finding. |
| **Static analysis stable identity** | Phase C — SARIF `partialFingerprints` | **OASIS SARIF 2.1** §3.27 (`result.partialFingerprints`, `fingerprints`) — vendor-neutral. **GitHub** Code Scanning and **GitLab** SAST consume SARIF fingerprints for stable issue identity across runs. |
| **Confidence tiers / no silent merge** | Goals + `correlation_scoring` + audit | **DefectDojo**: explicit dedupe algorithms vs legacy; inactive duplicates. Broader **GRC** practice: human review for exception workflows (not vendor-specific). |
| **Policy without code forks** (env, key version) | Env flags, correlation key prefix | **DefectDojo**: env overrides for `DD_HASHCODE_FIELDS_PER_SCANNER`. Enterprise products expose “dedupe strictness” or “match rules” in admin UI—same idea. |
| **Audit trail for duplicate/correlation** | §11; existing `emit_audit_event` | **SOC 2** / **ISO 27001**: change and decision logging (not a VMS feature—a **control** expectation VMS products implement). |

**How to use this table:** When implementing a row, read the **primary source** for field semantics (e.g. SARIF spec for fingerprints, DefectDojo for hash-field lists, OSV for package identity). VAT may simplify, but should not contradict the standard without documenting the deviation.

**Accuracy** in enterprise terms is **traceable decisions**: which fields, which policy version, which asset scope. This plan improves **reproducibility** (pure normalization, golden tests, versioned keys). Remaining risk is **scanner data quality**; the plan reduces **platform-induced** drift.

---

## 11. Enterprise Auditability (Explicit Requirements)

“Completely auditable” for SOC2/ISO-style reviews usually means: **every automated merge/link is explainable, replayable, and attributable; human overrides are separately logged.** The plan already assumes `apply_correlation_linking` audit events and correlation edges with evidence JSON. To make that **enterprise-complete**, treat the following as **first-class requirements** (some exist today; others should be tracked as acceptance criteria).

### 11.1 Must-Have (tie to phases or existing code)

| Requirement | Intent |
|-------------|--------|
| **Immutable audit trail** for dedup/correlation decisions | Append-only events (`dedup.correlation.linked`, `dedup.correlation.skipped`, ingest); no silent edits to historical decisions without a new event. |
| **Evidence on link** | Correlation edges already carry score/reasons/crosswalk; keep **inputs snapshot** sufficient to recompute or explain (e.g. correlation_key, key policy version, scanner ids). |
| **Fingerprint override audit** | `override_fingerprint` (and any admin merge) must emit **actor + reason + before/after** (verify/enhance if gaps). |
| **Tenant scope** | All correlation and audit queries respect `tenant_id` so multi-tenant audits are complete per customer. **Grounding:** `select_correlation_cluster` already filters by tenant — Phase A adds/verifies tests; any new correlation query must follow the same pattern. |
| **Reproducibility** | Documented field → key mapping + normalization version; golden tests per parser so behavior changes are **visible in CI**, not only in prod. |

### 11.2 Should-Have (strongly recommended)

| Requirement | Intent |
|-------------|--------|
| **Policy / rules version** | **`v1:` / `v2:` key prefix** on `correlation_key` (§4.4) is the primary version signal; add to edge evidence for redundancy. Optional DB column only if SQL analytics on version is required. |
| **Raw evidence retention** | Pointer (`raw_evidence_ref`) or hash to stored blob for disputes (“prove what the scanner sent”). Align with retention policy. |
| **Export / report** | API or export: “why is finding A linked to B?” (edge + evidence + timestamps). |
| **Separation of duties** | Role-gated fingerprint override and asset merge approval (if not already enforced in API). |

### 11.3 Plan Gap Closure

- Add **§11 acceptance criteria** to Phase A–E exit gates where relevant (e.g. Phase A: no regression on audit event payloads; Phase B: document normalization version in correlation evidence or key prefix).
- **Operational evidence:** `docs/audit-evidence-handoff-runbook.md` **exists** in-repo (audit export, ledger checkpoints). **Keep it in sync** when ingest contracts, audit event types, or evidence pointers change — treat updates as part of the same PR when those features ship (not a separate deferred doc task).
- Success metric addition: **“Third-party audit can reconstruct dedup/correlation decisions from DB + stored evidence pointers without reading application code.”**

---

## 12. References

### 12.1 Standards & specifications

| ID | Topic | URL / location |
|----|--------|----------------|
| SARIF 2.1 | `result.fingerprints`, `partialFingerprints` | [OASIS SARIF 2.1 — result object](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) |
| OSV | Vulnerability ↔ package identity | [OSV schema](https://ossf.github.io/osv-schema/) |
| CVE | Weakness identifier format | [CVE Program](https://www.cve.org/) / NVD |
| CycloneDX | Vuln linkage in SBOMs | [CycloneDX](https://cyclonedx.org/) specification |
| OCI | Image digest / manifest | [opencontainers/image-spec](https://github.com/opencontainers/image-spec) |
| XCCDF / STIG | Compliance rule identity (OpenSCAP ecosystem) | NIST / DISA checklist formats (see OpenSCAP project docs) |

### 12.2 Open-source VMS / platforms (reference implementations)

| System | What we borrow | Where to read |
|--------|----------------|---------------|
| **DefectDojo** | Hash-based dedup, per-scanner hash fields, `unique_id_from_tool`, product/engagement scope, service in hash | In-repo: `django-DefectDojo/docs/content/triage_findings/finding_deduplication/about_deduplication.md`; `dojo/finding/deduplication.py`; `dojo/settings/settings.dist.py` (`HASHCODE_FIELDS_PER_SCANNER`, `DEDUPE_ALGOS`) |
| **OWASP Dependency-Track** | Component + vuln graph, consistent package identity | [Dependency-Track documentation](https://docs.dependencytrack.org/) (component & vulnerability model) |
| **GitHub** | SARIF ingestion, code scanning workflow | [GitHub Code Scanning — SARIF](https://docs.github.com/en/code-security/code-scanning) |
| **GitLab** | SARIF as interchange for SAST | [GitLab SARIF](https://docs.gitlab.com/ee/ci/testing/sast.html) (SAST → SARIF) |

### 12.3 Commercial VMS (public documentation — patterns only)

These are **not** copied line-by-line; they illustrate how **enterprise products** scope findings. Use for requirements parity, not implementation detail.

| Vendor / product | Pattern | Typical public keyword |
|------------------|---------|-------------------------|
| **Tenable** (Nessus / Tenable.io) | Plugin ID + asset context | “plugin”, “asset”, vulnerability merge |
| **Qualys** | QID + host/asset | “QID”, “host based” |
| **Rapid7** (InsightVM / Nexpose) | Vulnerability ID + asset | “vulnerability”, “asset group” |
| **Snyk** | Package + issue / CVE grouping | Snyk API / Projects docs (“issues”, “dependencies”) |

### 12.4 Internal VAT docs

- `docs/correlation-linking-architecture.md`
- `docs/correlation-field-matrix.md` (Phase B deliverable — fingerprint vs correlation vs grouping)
- `docs/implementation-plan-grouping-model.md`
- `docs/audit-evidence-handoff-runbook.md` — **exists**; audit export / handoff for reviews; **update when** ingest or audit event contracts change

---

## 13. External Review — Validation Notes (v1.2)

An independent review proposed several refinements. **Assessment:**

| Observation | Valid? | Action in this plan |
|---------------|--------|---------------------|
| `partialFingerprints` needs precedence policy | **Yes** | §4.5 documents key order + fallback hash. |
| Normalization module boundary | **Yes** | §4.3 — pure functions only; side effects in other layers. |
| Key prefix vs version column | **Yes** | §4.4 — **prefix chosen**; column deferred. |
| Phase C line-shift exit criteria underspecified | **Yes** | Phase C **exit criteria** and §4.6 — explicit include/exclude line rules. |
| `scanner_identity` hierarchy | **Yes** | §4.6 — documented order with `partialFingerprints` before computed fallback. |
| Correlation **O(n²)** risk | **Partially** | Current implementation is **O(k)** per ingest for cluster size **k** (star scoring to canonical), not global n². Risk is **large k** — §6 risk row updated accordingly. |
| `new_scanner_stub.py` cost | **Yes** | Phase E — stub optional; cadence-based. |
| Tenant scope not grounded in phases | **Yes** | Phase A exit + §11.1 + risk register. |
| Field matrix as concrete deliverable | **Yes** | Phase B — `docs/correlation-field-matrix.md`. |

---

## 14. External Review — Validation Notes (v1.3, final polish)

Second-pass review (minor items only). **Assessment:**

| Observation | Valid? | Action in this plan |
|---------------|--------|---------------------|
| `audit-evidence-handoff-runbook.md` dangling pointer | **Partially** — file **exists** (`docs/audit-evidence-handoff-runbook.md`) with real content; gap was **missing “exists + sync”** in §11.3 / §12.4 | §11.3 and §12.4 now state existence and **sync obligation** with ingest/audit changes. |
| Phase D exit criteria too qualitative | **Yes** | Phase D **exit criteria** expanded with API/badge field, integration tests, digest flag test, doc cross-reference. |
| Stub cadence operationalized | **Yes** | Phase E — **one-time git-history heuristic** (<4 parser adds in 12 months → skip stub). |
| Field matrix before normalization code | **Yes** | Phase B — **sequence** block: matrix first, then code; exit criteria updated. |
| §13 as review pattern | **Acknowledged** | Keep §13 for first review; **§14** for second — traceable review cycle. |
