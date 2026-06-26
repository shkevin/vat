# Finding Evidence Detail Design

**Goal:** Make the VAT finding detail panel useful enough for a reviewer to understand what the issue is, where it is, what proof VAT has, and what action is expected without leaving VAT first.

**Primary Surface:** VAT frontend detail panel. Linear issue body improvements can reuse the same evidence data later, but they are not the first implementation target.

**Current State:** VAT already stores and displays several evidence-like fields: `description`, `file_path`, `line`, `source_file_url`, `snippet_masked`, `rule_id`, `cwe_id`, `resource`, `benchmark_id`, and `benchmark_family`. The local scanner also has snippet enrichment and a `--no-snippets` option. The problem is that these fields are sparse, scanner-specific, and rendered as incidental metadata rather than as a coherent reviewer evidence block.

---

## Design

Add a first-class **Evidence** section to the finding detail panel. The section should normalize existing fields into a consistent reviewer narrative:

- **What failed:** rule/check/CVE identity, title, severity, finding type, and scanner source.
- **Where:** file, line, Kubernetes object, image, package, resource, benchmark, or source link.
- **Proof:** masked snippet or scanner check output when present.
- **Why it matters:** the existing Markdown description plus references.
- **What to do next:** remediation guidance when parsers can extract it, otherwise a clear fallback based on finding type.

The first implementation should not require a large database migration. It should start by building a frontend evidence view model from fields VAT already returns. Parser and schema expansion should be planned as phase two once the UI has a stable shape.

## Evidence Types

VAT findings come from different evidence classes. The UI should not pretend every finding has a code snippet.

- **Source-backed findings:** SAST, secrets, SARIF, Gitleaks, Semgrep, and filesystem Trivy findings can show file path, line, source link, and masked snippet.
- **Kubernetes manifest findings:** operator `scan-k8s-inventory` findings can show the Kubernetes asset, object manifest path, rule ID, and masked YAML/config preview when Trivy provides or VAT enriches it.
- **Image/package findings:** image SCA and license findings usually have package, installed version, image, digest, CVE/reference, CVSS/EPSS, and remediation/version guidance rather than snippets.
- **OpenSCAP findings:** STIG/OVAL findings should emphasize benchmark/profile, rule ID, result state, check message, extracted file path, references, and remediation/rationale when available.

## Data Shape

Use a frontend-only evidence model first:

```ts
type FindingEvidenceView = {
  summary: Array<{ label: string; value: string; href?: string }>;
  proof?: {
    label: string;
    language?: "text" | "yaml" | "shell" | "json";
    content: string;
    masked: boolean;
  };
  explanation?: string;
  remediation?: string;
  references: Array<{ label: string; href?: string }>;
  warnings: string[];
};
```

This model should be derived from `Finding` in the frontend, not stored in state as a new API contract yet. That keeps the first change reversible and lets the team learn which parser fields are actually missing.

## UI Placement

Place **Evidence** near the top of `DetailPanel`, after the existing scope summary and before feed provenance/subissues/tracking. Keep the current scope card, but move the line preview out of the key/value grid and into the evidence proof block.

Recommended layout:

1. **Evidence Summary:** compact key/value rows for location, affected component/package, rule, benchmark, source, and source link.
2. **Proof:** a bordered code/pre block for `snippetMasked` or scanner output. Label it `Masked line preview`, `Scanner message`, or `Check output`.
3. **Explanation:** existing Markdown description through `FindingDescription`.
4. **Reviewer Next Step:** generated fallback copy based on finding type when no parser remediation exists.

For grouped findings, show evidence for the selected instance first. The existing subissues list can keep per-instance snippets, but each subissue card should eventually use the same evidence helper.

## Privacy And Safety

Evidence must preserve the current intent of `snippet_masked`: snippets may be useful, but raw secrets should not be stored or shown.

- Treat `snippetMasked` as displayable only if it came through a masking path.
- Keep `--no-snippets` meaningful. The scanner currently strips snippets before enrichment in some push flows, which can re-add previews. The implementation should ensure no enrichment happens when snippets are disabled.
- Avoid adding Secret object values from the Kubernetes operator. Operator inventory should continue storing Secret metadata only unless a future explicit opt-in is added.
- Cap proof content length in both backend parser extraction and frontend rendering.

## Implementation Plan

### Task 1: Add Frontend Evidence View Model

**Files:**

- Create: `frontend/lib/findingEvidence.ts`
- Test: `frontend/lib/findingEvidence.test.ts`

**Steps:**

1. Add `buildFindingEvidence(finding, options)` that derives the evidence model from existing `Finding` fields.
2. Cover SAST/Secret with file, line, and snippet.
3. Cover Kubernetes IaC with `image`/asset, `filePath`, `resource`, and rule.
4. Cover SCA/License with package/component, image, digest, CVE, CVSS/EPSS, and references when present.
5. Cover OpenSCAP with benchmark/profile/rule fields and check output from `snippetMasked`.
6. Run frontend tests for the helper.

### Task 2: Render Evidence In Detail Panel

**Files:**

- Modify: `frontend/components/detail/DetailPanel.tsx`
- Reuse: `frontend/components/detail/FindingDescription.tsx`

**Steps:**

1. Add an **Evidence** section after the scope card.
2. Render summary rows with links for repository/source URLs when available.
3. Render proof blocks with existing `detail-panel-snippet` styling.
4. Render description Markdown as the explanation body.
5. Remove or suppress the old line preview row in the scope grid when the new Evidence section renders proof.
6. Keep grouped/subissue behavior intact.

### Task 3: Tighten Snippet Opt-Out

**Files:**

- Modify: `vat-local-scanner/vat_scanner/cli.py`
- Test: `vat-local-scanner/tests/test_scan_cli_core.py` or `vat-local-scanner/tests/test_k8s_inventory_scan.py`

**Steps:**

1. Ensure `--no-snippets` skips enrichment as well as stripping existing snippet-like fields.
2. Add a test proving `--no-snippets` does not re-add `Content`, `lines`, or `snippet_masked` style evidence.
3. Keep snippets enabled by default for non-secret source/config findings.

### Task 4: Parser Enrichment Follow-Up

**Files:**

- Modify later: `backend/app/parsers/trivy.py`
- Modify later: `backend/app/parsers/openscap.py`
- Modify later: `backend/app/parsers/openscap_oval.py`
- Consider later: `backend/app/schemas/vat.py`, `backend/app/models/finding.py`, Alembic migration

**Steps:**

1. Improve Trivy misconfiguration parsing for message, cause metadata, file path, line, and YAML context.
2. Extract OpenSCAP rationale/fix/check text where available.
3. Decide whether a structured `evidence` JSONB column is justified after the first UI pass.
4. If adding `evidence`, keep old fields as compatibility projections for existing UI/export code.

## Acceptance Criteria

- A reviewer can open a finding and immediately see an **Evidence** section.
- Findings with snippets show them as proof, not as a hidden row in metadata.
- Findings without snippets still show useful evidence and next-step guidance.
- The first pass does not require database migration.
- `--no-snippets` remains a reliable privacy control.
- Existing description rendering, subissue grouping, and tracker sync continue to work.

## Non-Goals

- Do not add raw secret capture.
- Do not require source repository access from the Kubernetes operator.
- Do not overhaul Linear issue templates in the first pass.
- Do not replace existing finding grouping or correlation behavior.

## Verification

Run the focused frontend helper tests and detail-panel lint/type checks:

```bash
cd frontend
npm run test -- lib/findingEvidence.test.ts
npm run lint
```

Run scanner tests if changing snippet opt-out:

```bash
cd vat-local-scanner
PYTHONPATH=. uv run pytest tests/test_scan_cli_core.py tests/test_k8s_inventory_scan.py
```
