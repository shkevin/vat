# Scanner Correlation Readiness

This document tracks which scanners are ready for deterministic cross-source correlation and which still need testing or adapter updates.

## Purpose

- Keep deterministic auto-link behavior reliable at scale.
- Make scanner onboarding measurable.
- Track gaps in payload identity quality (asset/rule/package fields).

## Correlation contract (what every scanner must provide)

Deterministic linking depends on these inputs after parser normalization and backend enrichment:

- **Asset identity (required for strong matching)**
  - Prefer: `image`, `branch`, `tag`
  - Fallback: `component` when asset fields are unavailable
- **Correlation evidence (required for high/medium tiers)**
  - SCA/license: `cve_id`, `component`/`component_base`, optional `ecosystem`
  - SAST/IaC/Secrets: `rule_id` and preferably `file_path`
  - OpenSCAP/STIG: `stable_rule_key`, `benchmark_family`, `profile_scope` (plus asset)
- **Tenant scope**
  - `tenant_id` must be correct; correlation is tenant-isolated.

VAT backend owns normalization/enrichment and should derive missing identifiers when possible. If fields remain sparse or inconsistent after enrichment, findings will trend to `low` and be skipped.

## Readiness status definitions

- **Validated**: deterministic link behavior verified for core scenarios.
- **Partial**: parser appears compatible but needs broader coverage or edge-case validation.
- **Needs testing**: no dedicated correlation readiness validation completed yet.
- **Needs adaptation**: known payload/normalization gaps block reliable correlation.

## Scanner readiness matrix

| Parser ID | Primary finding types | Identity policy hints | Current status | Notes / likely risk |
|---|---|---|---|---|
| `trivy` | SCA, secrets, license, misconfig | strong fields: target image refs | Partial | Usually strong for SCA; verify non-SCA consistency. |
| `grype` | SCA | strong fields: target input | Partial | Good CVE/package signal; verify asset normalization parity vs Trivy. |
| `snyk` | SCA, container vulns | strong fields: `targetFile`, `projectName` | Needs testing | Project naming can vary; validate canonical asset mapping. |
| `cyclonedx` | SBOM vulnerabilities | strong fields: metadata/component props | Needs testing | Depends on SBOM completeness and component normalization. |
| `npm_audit` | SCA (Node) | nodes/findings paths | Needs testing | Asset identity may be weak in some CI contexts. |
| `pip_audit` | SCA (Python) | dependency names | Needs testing | Requires reliable asset context from ingest caller. |
| `openscap` | Compliance/STIG | target + target-address | Partial | Verify STIG stable rule normalization across content revisions. |
| `openscap_oval` | Compliance/CVE | hostname/system fields | Needs testing | Validate asset identity quality for image/host scans. |
| `semgrep` | SAST | strong field: result path | Needs testing | Rule+path should correlate; verify repo/branch/tag normalization. |
| `sarif` | Multi-tool static results | artifact URI fields | Needs adaptation | Generic SARIF variability may require tool-specific normalization. |
| `gitleaks` | Secrets | target/file fields | Needs testing | Ensure deterministic grouping for same secret across scans. |
| `canonical` | Any (already-normalized) | explicit `image|branch|tag` recommended | Partial | Depends on upstream producer quality. |

## Per-scanner validation checklist

Run this for each parser and mark completion in PRs.

1. **Asset-gated linking**
   - Same asset + same evidence => auto-link (`high` or `medium`)
   - Different asset + same evidence => skip (`low`, asset mismatch)
2. **Tenant isolation**
   - Same `correlation_key` across different tenants never links
3. **Determinism**
   - Repeated ingest yields stable canonical root (`created_at`, `id`)
   - Re-running correlation does not create inconsistent pointer flips
4. **Evidence quality**
   - SCA: CVE + package/component preserved
   - Code scanners: rule/path preserved
   - OpenSCAP: stable rule key and benchmark family preserved
5. **Merge parity**
   - Manual asset merge post-pass applies same policy for moved findings
   - Merge execution is blocked unless the source/target pair has an approved `asset_merge_reviews` entry
6. **Auditability**
   - `dedup.correlation.linked` or `dedup.correlation.skipped` emitted with reason codes
   - `correlation_edges` evidence populated for linked pairs

## Adaptation backlog template

Use this section to track scanner-specific parser updates.

| Scanner | Gap | Required change | Owner | Priority | Status |
|---|---|---|---|---|---|
| Example: `sarif` | Missing stable asset field in some tool exports | Add parser fallback for repo/ref from run metadata | TBD | P1 | Open |

## Suggested test organization

Add parser-focused readiness tests under:

- `backend/tests/integration/` for end-to-end parser + ingest + correlation behavior
- `backend/tests/test_*parser*.py` for parser normalization guarantees

Keep deterministic policy checks centralized with:

- `backend/tests/test_correlation_linking.py`
- `backend/tests/integration/test_correlation_linking_integration.py`
- `backend/tests/test_assets_api.py` (manual merge parity path)

