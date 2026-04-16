# Feed Correlation v2 Rubric (SBOM <-> Threat Intel)

**Status:** Draft for implementation  
**Applies to:** `backend/app/services/vuln_feeds.py` correlation + materialization path

## 1) Goal

Provide a deterministic, explainable, and low-noise way to correlate SBOM components with advisory intel and materialize only appropriate findings.

This rubric standardizes:

- Match confidence (`high`, `medium`, `low`)
- Match strategy tags
- Materialization eligibility rules
- False-positive guardrails
- Audit and observability signals

## 2) Scope in current VAT pipeline

The rubric is intended for:

- advisory ingestion normalization (`vuln_feed_records`)
- SBOM correlation and finding materialization (`materialize_feed_matches_to_findings`)
- asset intel explanation (`get_asset_vuln_intel`)
- UI provenance (`sources[].matchStrategy`, `sources[].matchConfidence`)

## 3) Normalization prerequisites

Before scoring a match, normalize both SBOM and advisory identity:

- **Package name:** lowercase, trim; preserve scoped names (e.g. `@scope/pkg`)
- **Ecosystem:** normalized canonical value (`npm`, `pypi`, `maven`, etc.)
- **Version:** trim, preserve exact string for now; parse/compare ranges when available in v2.1
- **Identifiers:** prefer CVE/GHSA/OSV id where present

If package name cannot be normalized on either side, correlation result is `no_match`.

## 4) Decision matrix (confidence + strategy)

| Condition | Strategy | Confidence | Materialize default |
|---|---|---|---|
| package name + ecosystem + exact version match | `name+version+ecosystem` | `high` | yes |
| package name + exact version match (ecosystem missing on one side) | `name+version` | `medium` | yes |
| package name + ecosystem match, advisory has no version | `name+ecosystem_no_version` | `medium` | yes (guarded) |
| package name match only, advisory has no version/ecosystem | `advisory-no-version` | `low` | no (default) |
| package name mismatch | `name_mismatch` | `low` | no |
| advisory has version and version != SBOM version | `version_mismatch` | `low` | no |

## 5) Materialization policy

Default policy for `v2`:

- **Materialize:** `high`, `medium`
- **Do not materialize by default:** `low`
- **Still expose in intel explorer:** all confidence levels

Optional feature flag:

- `VAT_FEED_MATCH_INCLUDE_LOW_CONFIDENCE=false` (default)
- If enabled, low-confidence matches can materialize but must be clearly marked in audit/UI.

## 6) False-positive guardrails

1. **Versionless advisory guardrail**
   - If advisory lacks version, require ecosystem alignment.
   - If ecosystem is also missing, keep as `low` and do not materialize by default.

2. **Ecosystem mismatch guardrail**
   - Do not elevate confidence when package names match but ecosystems disagree.

3. **Duplicate strategy guardrail**
   - Keep strategy-aware fingerprint identity to avoid accidental merge of distinct matching paths.

4. **Open-status-only auto-resolve**
   - Auto-resolve only open-like statuses.
   - Never override explicit suppression/false-positive workflow states.

5. **No-bulk fanout guardrail**
   - For a single advisory with missing version causing large fanout to one asset, cap materialization per advisory/asset pair unless confidence is `high`.

## 7) Required provenance fields

Every materialized finding must retain:

- `correlation_key`
- `correlation_confidence`
- in `sources[]` on `vuln_feed_match` entry:
  - `feedSource`
  - `matchStrategy`
  - `matchConfidence`
  - `matchedPackage`
  - `matchedVersion`
  - `matchedAsset`

This ensures deterministic traceability from finding -> match reasoning.

## 8) Audit payload requirements

`vuln_feed.materialize.completed` should include:

- counts: `created`, `updated`, `reopened`, `resolved`, `matched`
- `strategy_counts`
- `confidence_counts`
- optional: `excluded_low_confidence`, `excluded_version_mismatch`

Per-finding audit notes should include:

- advisory source
- package@version
- asset id
- strategy
- confidence

## 9) Accuracy scorecard (operational)

Track these weekly:

- `% high confidence materialized`
- `% low confidence surfaced but not materialized`
- reopen rate for feed-derived findings
- suppression rate for feed-derived findings
- duplicate ratio (`same cve_id + asset + component` created more than once)

Target baseline:

- `>= 80%` of materialized feed findings are `high`
- `< 10%` of materialized findings become suppressed/false-positive in 14 days

## 10) Recommended near-term implementation order

1. Enforce materialization threshold (`high|medium`) in `materialize_feed_matches_to_findings`
2. Add exclusion counters to audit payload
3. Add fanout guardrail for versionless advisories
4. Add dashboard card for confidence mix and suppression feedback

## 11) Example outcomes

- **Example A:** `next@15.5.10` advisory `npm` + exact version  
  -> `name+version+ecosystem`, `high`, materialize.

- **Example B:** package `foo`, advisory `foo`, advisory version missing, ecosystem `npm`  
  -> `name+ecosystem_no_version`, `medium`, materialize (guarded).

- **Example C:** package `foo`, advisory `foo`, no ecosystem/version in advisory  
  -> `advisory-no-version`, `low`, intel-only by default.
